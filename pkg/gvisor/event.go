package gvisor

import (
	"encoding/binary"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

// gVisorHeaderSize は gVisor の wire.Header (gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote/wire) のサイズ。
//
//	0 --------- 16 ---------- 32 ----------- 64 -----------+
//	| HeaderSize | MessageType | DroppedCount | Payload... |
//	+---- 16 ----+---- 16 -----+----- 32 -----+------------+
const gVisorHeaderSize = 8

// gVisorProtocolVersion は gVisor の wire.CurrentVersion に対応するハンドシェイクのバージョン。
const gVisorProtocolVersion = 1

// gVisor の remote sink は wire.Header (8 byte) + protobuf ペイロードを 1 パケットとして送ってくる。
// プラグインはこのパケットをそのまま Falco のイベントデータとして扱い、
// フィールド抽出時にデコードする。こうすることで Falco のキャプチャファイルにも
// 元のメッセージがそのまま保存される。

// gVisorEvent は gVisor から受け取ったメッセージを、フィールド抽出に必要な形にデコードしたもの。
type gVisorEvent struct {
	MessageType   pb.MessageType
	DroppedCount  uint32
	Message       proto.Message
	ContextData   *pb.ContextData
	SyscallNumber uint64
	HasSyscall    bool
	// IsSyscallExit は syscall の exit point で記録されたイベントかどうか。
	// gVisor は exit point のときだけ Exit (戻り値・errno) を設定する。
	IsSyscallExit bool
}

// EventDirection は Falco の evt.dir と同様に、enter なら ">"、exit なら "<" を返す。
func (event *gVisorEvent) EventDirection() string {
	if event.IsSyscallExit {
		return "<"
	}
	return ">"
}

// EventType は Falco の evt.type と同様の値 (例: "openat", "execve") を返す。
func (event *gVisorEvent) EventType() string {
	if event.HasSyscall {
		if syscallName, found := syscallNamesByNumber[event.SyscallNumber]; found {
			return syscallName
		}
	}
	return fallbackEventTypeName(event.MessageType)
}

// ProcessName は Falco の proc.name と同様の値 (実行ファイル名) を返す。
// gVisor の trace session で context_fields に "process_name" を指定していない場合は空になる。
func (event *gVisorEvent) ProcessName() string {
	return event.ContextData.GetProcessName()
}

// fallbackEventTypeName は syscall 番号から名前が引けない場合の evt.type を
// メッセージ種別から作る。
//
//	MESSAGE_SYSCALL_OPEN    -> "open"
//	MESSAGE_SENTRY_CLONE    -> "sentry_clone"
//	MESSAGE_CONTAINER_START -> "container_start"
func fallbackEventTypeName(messageType pb.MessageType) string {
	enumName, found := pb.MessageType_name[int32(messageType)]
	if !found {
		return fmt.Sprintf("unknown_%d", messageType)
	}
	enumName = strings.TrimPrefix(enumName, "MESSAGE_")
	enumName = strings.TrimPrefix(enumName, "SYSCALL_")
	return strings.ToLower(enumName)
}

// newMessageForType はメッセージ種別に対応する protobuf メッセージを生成する。
func newMessageForType(messageType pb.MessageType) (proto.Message, error) {
	switch messageType {
	case pb.MessageType_MESSAGE_CONTAINER_START:
		return &pb.Start{}, nil
	case pb.MessageType_MESSAGE_SENTRY_CLONE:
		return &pb.CloneInfo{}, nil
	case pb.MessageType_MESSAGE_SENTRY_EXEC:
		return &pb.ExecveInfo{}, nil
	case pb.MessageType_MESSAGE_SENTRY_EXIT_NOTIFY_PARENT:
		return &pb.ExitNotifyParentInfo{}, nil
	case pb.MessageType_MESSAGE_SENTRY_TASK_EXIT:
		return &pb.TaskExit{}, nil
	case pb.MessageType_MESSAGE_SENTRY_MMAP:
		return &pb.MmapInfo{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_RAW:
		return &pb.Syscall{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_OPEN:
		return &pb.Open{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_CLOSE:
		return &pb.Close{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_READ:
		return &pb.Read{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_WRITE:
		return &pb.Write{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_CONNECT:
		return &pb.Connect{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_EXECVE:
		return &pb.Execve{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_SOCKET:
		return &pb.Socket{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_CHDIR:
		return &pb.Chdir{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_SETID:
		return &pb.Setid{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_SETRESID:
		return &pb.Setresid{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_PRLIMIT64:
		return &pb.Prlimit{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_PIPE:
		return &pb.Pipe{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_FCNTL:
		return &pb.Fcntl{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_DUP:
		return &pb.Dup{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_SIGNALFD:
		return &pb.Signalfd{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_CHROOT:
		return &pb.Chroot{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_EVENTFD:
		return &pb.Eventfd{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_CLONE:
		return &pb.Clone{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_BIND:
		return &pb.Bind{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_ACCEPT:
		return &pb.Accept{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_LISTEN:
		return &pb.Listen{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_TIMERFD_CREATE:
		return &pb.TimerfdCreate{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_TIMERFD_SETTIME:
		return &pb.TimerfdSetTime{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_TIMERFD_GETTIME:
		return &pb.TimerfdGetTime{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_FORK:
		return &pb.Fork{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_INOTIFY_INIT:
		return &pb.InotifyInit{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_INOTIFY_ADD_WATCH:
		return &pb.InotifyAddWatch{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_INOTIFY_RM_WATCH:
		return &pb.InotifyRmWatch{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_SOCKETPAIR:
		return &pb.SocketPair{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_MMAP:
		return &pb.Mmap{}, nil
	case pb.MessageType_MESSAGE_SYSCALL_PTRACE:
		return &pb.Ptrace{}, nil
	default:
		return nil, fmt.Errorf("unsupported gVisor message type: %d", messageType)
	}
}

// decodeGVisorEvent は wire.Header + protobuf ペイロードからなるパケットをデコードする。
func decodeGVisorEvent(packet []byte) (*gVisorEvent, error) {
	if len(packet) < gVisorHeaderSize {
		return nil, fmt.Errorf("gVisor packet too short: %d bytes", len(packet))
	}
	// gVisor はホストのバイトオーダーでヘッダを書き込む。gVisor が動作する
	// amd64 / arm64 はいずれもリトルエンディアン。
	headerSize := int(binary.LittleEndian.Uint16(packet[0:2]))
	messageType := pb.MessageType(binary.LittleEndian.Uint16(packet[2:4]))
	droppedCount := binary.LittleEndian.Uint32(packet[4:8])
	if headerSize < gVisorHeaderSize || headerSize > len(packet) {
		return nil, fmt.Errorf("invalid gVisor header size: %d (packet %d bytes)", headerSize, len(packet))
	}

	message, err := newMessageForType(messageType)
	if err != nil {
		return nil, err
	}
	if err := proto.Unmarshal(packet[headerSize:], message); err != nil {
		return nil, fmt.Errorf("unmarshalling gVisor message (type %d): %w", messageType, err)
	}

	event := &gVisorEvent{
		MessageType:  messageType,
		DroppedCount: droppedCount,
		Message:      message,
	}
	// 生成された全メッセージ型は GetContextData を持ち、syscall 系は GetSysno を持つ。
	if messageWithContext, ok := message.(interface{ GetContextData() *pb.ContextData }); ok {
		event.ContextData = messageWithContext.GetContextData()
	}
	if messageWithSyscall, ok := message.(interface{ GetSysno() uint64 }); ok {
		event.SyscallNumber = messageWithSyscall.GetSysno()
		event.HasSyscall = true
	}
	if messageWithExit, ok := message.(interface{ GetExit() *pb.Exit }); ok {
		event.IsSyscallExit = messageWithExit.GetExit() != nil
	}
	return event, nil
}

// encodeGVisorPacket は gVisor の remote sink と同じ形式でパケットを組み立てる (テスト用)。
func encodeGVisorPacket(messageType pb.MessageType, message proto.Message) ([]byte, error) {
	payload, err := proto.Marshal(message)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, gVisorHeaderSize, gVisorHeaderSize+len(payload))
	binary.LittleEndian.PutUint16(packet[0:2], gVisorHeaderSize)
	binary.LittleEndian.PutUint16(packet[2:4], uint16(messageType))
	return append(packet, payload...), nil
}
