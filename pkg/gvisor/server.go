package gvisor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"google.golang.org/protobuf/proto"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

// gVisorEventServer は gVisor (runsc) の remote sink からの接続を受け付ける
// SOCK_SEQPACKET の Unix ドメインソケットサーバ。
//
// gVisor の remote sink はサンドボックスごとにクライアントとして接続してくるため、
// 複数のサンドボックスから同時に接続されることを想定している。
type gVisorEventServer struct {
	socketPath   string
	maxEventSize uint32
	events       chan<- source.PushEvent

	listener *net.UnixListener
	cancel   context.CancelFunc

	connectionsMutex  sync.Mutex
	activeConnections map[*net.UnixConn]struct{}
	waitGroup         sync.WaitGroup
}

func newGVisorEventServer(socketPath string, maxEventSize uint32, events chan<- source.PushEvent) *gVisorEventServer {
	return &gVisorEventServer{
		socketPath:        socketPath,
		maxEventSize:      maxEventSize,
		events:            events,
		activeConnections: make(map[*net.UnixConn]struct{}),
	}
}

// Start はソケットを作成し、接続の受け付けを開始する。
func (server *gVisorEventServer) Start() error {
	// 前回の実行で残ったソケットファイルがあると bind に失敗するため削除する。
	if err := os.Remove(server.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing stale socket %q: %w", server.socketPath, err)
	}
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: server.socketPath, Net: "unixpacket"})
	if err != nil {
		return fmt.Errorf("listening on %q: %w", server.socketPath, err)
	}
	server.listener = listener

	serverContext, cancel := context.WithCancel(context.Background())
	server.cancel = cancel

	server.waitGroup.Add(1)
	go server.acceptLoop(serverContext)
	return nil
}

// Stop は受け付けを停止し、全ての接続を閉じて goroutine の終了を待つ。
func (server *gVisorEventServer) Stop() {
	server.cancel()
	_ = server.listener.Close()

	server.connectionsMutex.Lock()
	for connection := range server.activeConnections {
		_ = connection.Close()
	}
	server.connectionsMutex.Unlock()

	server.waitGroup.Wait()
	_ = os.Remove(server.socketPath)
}

func (server *gVisorEventServer) acceptLoop(serverContext context.Context) {
	defer server.waitGroup.Done()
	for {
		connection, err := server.listener.AcceptUnix()
		if err != nil {
			if serverContext.Err() != nil {
				return
			}
			server.pushError(serverContext, fmt.Errorf("accepting gVisor connection: %w", err))
			return
		}

		server.connectionsMutex.Lock()
		server.activeConnections[connection] = struct{}{}
		server.connectionsMutex.Unlock()

		server.waitGroup.Add(1)
		go server.handleConnection(serverContext, connection)
	}
}

func (server *gVisorEventServer) handleConnection(serverContext context.Context, connection *net.UnixConn) {
	defer server.waitGroup.Done()
	defer func() {
		server.connectionsMutex.Lock()
		delete(server.activeConnections, connection)
		server.connectionsMutex.Unlock()
		_ = connection.Close()
	}()

	if err := performHandshake(connection); err != nil {
		// 1 つのサンドボックスとのハンドシェイク失敗でプラグイン全体を止めないよう、接続だけ閉じる。
		fmt.Fprintf(os.Stderr, "gvisor plugin: handshake failed: %v\n", err)
		return
	}

	// PID はサンドボックスごとに独立しているため、プロセス表は接続ごとに持つ。
	processes := newProcessTable()
	packetBuffer := make([]byte, server.maxEventSize)
	for {
		packetLength, _, receiveFlags, _, err := connection.ReadMsgUnix(packetBuffer, nil)
		if err != nil {
			// サンドボックスの終了 (EOF) や Stop によるクローズは正常終了として扱う。
			return
		}
		if packetLength == 0 {
			// SOCK_SEQPACKET では長さ 0 の読み込みは相手側のクローズを意味する。
			return
		}
		if receiveFlags&syscall.MSG_TRUNC != 0 {
			fmt.Fprintf(os.Stderr, "gvisor plugin: dropped message larger than maxEventSize (%d bytes)\n", server.maxEventSize)
			continue
		}

		pushEvent, err := buildPushEvent(processes, packetBuffer[:packetLength])
		if err != nil {
			fmt.Fprintf(os.Stderr, "gvisor plugin: dropped message: %v\n", err)
			continue
		}

		select {
		case server.events <- pushEvent:
		case <-serverContext.Done():
			return
		}
	}
}

// buildPushEvent は gVisor のパケットでプロセス表を更新し、
// プロセス情報を埋め込んだ Falco のイベントを作る。
func buildPushEvent(processes *processTable, packet []byte) (source.PushEvent, error) {
	event, err := decodeGVisorEvent(packet)
	if err != nil {
		return source.PushEvent{}, err
	}
	processContext := processes.recordEvent(event)
	// encodeEnrichedEvent は新しいバッファにコピーするため、packet (受信バッファ) は再利用してよい。
	eventData, err := encodeEnrichedEvent(processContext, packet)
	if err != nil {
		return source.PushEvent{}, err
	}
	pushEvent := source.PushEvent{Data: eventData}
	if timeNs := event.ContextData.GetTimeNs(); timeNs > 0 {
		pushEvent.Timestamp = time.Unix(0, timeNs)
	}
	return pushEvent, nil
}

// performHandshake は gVisor の remote sink とのハンドシェイクを行う。
// クライアント (gVisor) が先に Handshake メッセージを送り、サーバが自身の Handshake を返す。
func performHandshake(connection *net.UnixConn) error {
	handshakeBuffer := make([]byte, 10240)
	readLength, err := connection.Read(handshakeBuffer)
	if err != nil {
		return fmt.Errorf("reading handshake: %w", err)
	}
	clientHandshake := &pb.Handshake{}
	if err := proto.Unmarshal(handshakeBuffer[:readLength], clientHandshake); err != nil {
		return fmt.Errorf("unmarshalling handshake: %w", err)
	}
	if clientHandshake.GetVersion() < gVisorProtocolVersion {
		return fmt.Errorf("unsupported gVisor protocol version %d", clientHandshake.GetVersion())
	}

	serverHandshake, err := proto.Marshal(&pb.Handshake{Version: gVisorProtocolVersion})
	if err != nil {
		return fmt.Errorf("marshalling handshake: %w", err)
	}
	if _, err := connection.Write(serverHandshake); err != nil {
		return fmt.Errorf("writing handshake: %w", err)
	}
	return nil
}

func (server *gVisorEventServer) pushError(serverContext context.Context, err error) {
	select {
	case server.events <- source.PushEvent{Err: err}:
	case <-serverContext.Done():
	}
}
