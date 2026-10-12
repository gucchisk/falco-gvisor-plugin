package gvisor

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"google.golang.org/protobuf/proto"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

// connectAsGVisorSink は gVisor の remote sink と同じ手順でサーバに接続する。
func connectAsGVisorSink(t *testing.T, socketPath string) *net.UnixConn {
	t.Helper()
	connection, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: socketPath, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	clientHandshake, _ := proto.Marshal(&pb.Handshake{Version: gVisorProtocolVersion})
	if _, err := connection.Write(clientHandshake); err != nil {
		t.Fatal(err)
	}
	handshakeBuffer := make([]byte, 1024)
	readLength, err := connection.Read(handshakeBuffer)
	if err != nil {
		t.Fatal(err)
	}
	serverHandshake := &pb.Handshake{}
	if err := proto.Unmarshal(handshakeBuffer[:readLength], serverHandshake); err != nil {
		t.Fatal(err)
	}
	if serverHandshake.GetVersion() != gVisorProtocolVersion {
		t.Fatalf("server handshake version = %d", serverHandshake.GetVersion())
	}
	return connection
}

func TestServerReceivesEventsFromGVisorSink(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gvisor.sock")
	events := make(chan source.PushEvent, 10)
	server := newGVisorEventServer(socketPath, defaultMaxEventSize, events)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Stop()

	connection := connectAsGVisorSink(t, socketPath)
	defer connection.Close()

	eventTime := time.Unix(1700000000, 123)
	packet := mustEncodePacket(t, pb.MessageType_MESSAGE_SYSCALL_EXECVE, &pb.Execve{
		ContextData: &pb.ContextData{ProcessName: "bash", TimeNs: eventTime.UnixNano()},
		Pathname:    "/bin/ls",
	})
	if _, err := connection.Write(packet); err != nil {
		t.Fatal(err)
	}

	select {
	case pushEvent := <-events:
		if pushEvent.Err != nil {
			t.Fatal(pushEvent.Err)
		}
		if !pushEvent.Timestamp.Equal(eventTime) {
			t.Errorf("timestamp = %v, want %v", pushEvent.Timestamp, eventTime)
		}
		event, err := decodeGVisorEvent(pushEvent.Data)
		if err != nil {
			t.Fatal(err)
		}
		if event.ProcessName() != "bash" {
			t.Errorf("proc.name = %q, want bash", event.ProcessName())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestServerStopClosesActiveConnections(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gvisor.sock")
	server := newGVisorEventServer(socketPath, defaultMaxEventSize, make(chan source.PushEvent))
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	connection := connectAsGVisorSink(t, socketPath)
	defer connection.Close()

	stopped := make(chan struct{})
	go func() {
		server.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return")
	}
}
