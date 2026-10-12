package gvisor

import (
	"bytes"
	"io"
	"runtime"
	"testing"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"google.golang.org/protobuf/proto"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

type fakeEventReader struct {
	eventNumber uint64
	data        []byte
}

func (reader *fakeEventReader) EventNum() uint64      { return reader.eventNumber }
func (reader *fakeEventReader) Timestamp() uint64     { return 0 }
func (reader *fakeEventReader) Reader() io.ReadSeeker { return bytes.NewReader(reader.data) }

type fakeExtractRequest struct {
	fieldName      string
	extractedValue any
}

func (request *fakeExtractRequest) FieldID() uint64                                  { return 0 }
func (request *fakeExtractRequest) FieldType() uint32                                { return 0 }
func (request *fakeExtractRequest) Field() string                                    { return request.fieldName }
func (request *fakeExtractRequest) ArgKey() string                                   { return "" }
func (request *fakeExtractRequest) ArgIndex() uint64                                 { return 0 }
func (request *fakeExtractRequest) ArgPresent() bool                                 { return false }
func (request *fakeExtractRequest) IsList() bool                                     { return false }
func (request *fakeExtractRequest) SetValue(value interface{})                       { request.extractedValue = value }
func (request *fakeExtractRequest) SetValueOffset(start, length uint32)              {}
func (request *fakeExtractRequest) SetPtr(unsafe.Pointer)                            {}
func (request *fakeExtractRequest) SetOffsetPtrs(startPtr, lengthPtr unsafe.Pointer) {}
func (request *fakeExtractRequest) WantOffset() bool                                 { return false }

var _ sdk.ExtractRequest = (*fakeExtractRequest)(nil)

// openatSyscallNumber はテスト実行環境のアーキテクチャにおける openat の syscall 番号。
func openatSyscallNumber(t *testing.T) uint64 {
	switch runtime.GOARCH {
	case "amd64":
		return 257
	case "arm64":
		return 56
	default:
		t.Skipf("syscall table is not available on %s", runtime.GOARCH)
		return 0
	}
}

func extractField(t *testing.T, plugin *Plugin, eventReader sdk.EventReader, fieldName string) any {
	t.Helper()
	request := &fakeExtractRequest{fieldName: fieldName}
	if err := plugin.Extract(request, eventReader); err != nil {
		t.Fatalf("Extract(%s): %v", fieldName, err)
	}
	return request.extractedValue
}

func mustEncodePacket(t *testing.T, messageType pb.MessageType, message proto.Message) []byte {
	t.Helper()
	packet, err := encodeGVisorPacket(messageType, message)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func TestExtractTypedSyscall(t *testing.T) {
	openMessage := &pb.Open{
		ContextData: &pb.ContextData{
			ProcessName:   "cat",
			ContainerId:   "container-1",
			ThreadId:      42,
			ThreadGroupId: 40,
		},
		Sysno:    openatSyscallNumber(t),
		Pathname: "/etc/shadow",
	}
	eventReader := &fakeEventReader{eventNumber: 1, data: mustEncodePacket(t, pb.MessageType_MESSAGE_SYSCALL_OPEN, openMessage)}
	plugin := &Plugin{}

	expectedValues := map[string]any{
		"proc.name":           "cat",
		"evt.type":            "openat",
		"gvisor.sysno":        openatSyscallNumber(t),
		"gvisor.container_id": "container-1",
		"gvisor.pid":          uint64(40),
		"gvisor.tid":          uint64(42),
	}
	for fieldName, expectedValue := range expectedValues {
		if extractedValue := extractField(t, plugin, eventReader, fieldName); extractedValue != expectedValue {
			t.Errorf("%s = %v (%T), want %v (%T)", fieldName, extractedValue, extractedValue, expectedValue, expectedValue)
		}
	}
}

func TestExtractRawSyscall(t *testing.T) {
	rawSyscallMessage := &pb.Syscall{
		ContextData: &pb.ContextData{ProcessName: "sh"},
		Sysno:       openatSyscallNumber(t),
	}
	eventReader := &fakeEventReader{eventNumber: 2, data: mustEncodePacket(t, pb.MessageType_MESSAGE_SYSCALL_RAW, rawSyscallMessage)}
	plugin := &Plugin{}

	if eventType := extractField(t, plugin, eventReader, "evt.type"); eventType != "openat" {
		t.Errorf("evt.type = %v, want openat", eventType)
	}
	if processName := extractField(t, plugin, eventReader, "proc.name"); processName != "sh" {
		t.Errorf("proc.name = %v, want sh", processName)
	}
}

func TestExtractNonSyscallPoint(t *testing.T) {
	cloneMessage := &pb.CloneInfo{ContextData: &pb.ContextData{ProcessName: "bash"}}
	eventReader := &fakeEventReader{eventNumber: 3, data: mustEncodePacket(t, pb.MessageType_MESSAGE_SENTRY_CLONE, cloneMessage)}
	plugin := &Plugin{}

	if eventType := extractField(t, plugin, eventReader, "evt.type"); eventType != "sentry_clone" {
		t.Errorf("evt.type = %v, want sentry_clone", eventType)
	}
	if syscallNumber := extractField(t, plugin, eventReader, "gvisor.sysno"); syscallNumber != nil {
		t.Errorf("gvisor.sysno = %v, want no value", syscallNumber)
	}
	if eventDirection := extractField(t, plugin, eventReader, "evt.dir"); eventDirection != nil {
		t.Errorf("evt.dir = %v, want no value", eventDirection)
	}
}

func TestExtractEventDirection(t *testing.T) {
	testCases := []struct {
		name              string
		messageType       pb.MessageType
		message           proto.Message
		expectedDirection string
	}{
		{
			name:              "typed syscall enter",
			messageType:       pb.MessageType_MESSAGE_SYSCALL_EXECVE,
			message:           &pb.Execve{Sysno: 221},
			expectedDirection: ">",
		},
		{
			name:              "typed syscall exit",
			messageType:       pb.MessageType_MESSAGE_SYSCALL_EXECVE,
			message:           &pb.Execve{Sysno: 221, Exit: &pb.Exit{Result: 0}},
			expectedDirection: "<",
		},
		{
			name:              "raw syscall exit",
			messageType:       pb.MessageType_MESSAGE_SYSCALL_RAW,
			message:           &pb.Syscall{Sysno: 105, Exit: &pb.Exit{Result: -1, Errorno: 1}},
			expectedDirection: "<",
		},
	}
	for eventNumber, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			eventReader := &fakeEventReader{eventNumber: uint64(eventNumber), data: mustEncodePacket(t, testCase.messageType, testCase.message)}
			if eventDirection := extractField(t, &Plugin{}, eventReader, "evt.dir"); eventDirection != testCase.expectedDirection {
				t.Errorf("evt.dir = %v, want %s", eventDirection, testCase.expectedDirection)
			}
		})
	}
}

func TestEventTypeFallsBackToMessageTypeForUnknownSyscall(t *testing.T) {
	event := &gVisorEvent{MessageType: pb.MessageType_MESSAGE_SYSCALL_OPEN, SyscallNumber: 99999, HasSyscall: true}
	if eventType := event.EventType(); eventType != "open" {
		t.Errorf("EventType() = %q, want open", eventType)
	}
}

func TestDecodeRejectsMalformedPacket(t *testing.T) {
	if _, err := decodeGVisorEvent([]byte{1, 2, 3}); err == nil {
		t.Error("expected error for too short packet")
	}
	invalidHeaderSizePacket := []byte{0xff, 0x00, 0x07, 0x00, 0, 0, 0, 0}
	if _, err := decodeGVisorEvent(invalidHeaderSizePacket); err == nil {
		t.Error("expected error for invalid header size")
	}
}
