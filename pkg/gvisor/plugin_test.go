package gvisor

import (
	"bytes"
	"fmt"
	"io"
	"runtime"
	"strings"
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
	argumentIndex  uint64
	extractedValue any
}

func (request *fakeExtractRequest) FieldID() uint64                                  { return 0 }
func (request *fakeExtractRequest) FieldType() uint32                                { return 0 }
func (request *fakeExtractRequest) Field() string                                    { return request.fieldName }
func (request *fakeExtractRequest) ArgKey() string                                   { return "" }
func (request *fakeExtractRequest) ArgIndex() uint64                                 { return request.argumentIndex }
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

// newEnrichedEventReader は gVisor のメッセージにプロセス情報を付けた Falco のイベントを作る。
func newEnrichedEventReader(t *testing.T, eventNumber uint64, context processContext, messageType pb.MessageType, message proto.Message) *fakeEventReader {
	t.Helper()
	eventData, err := encodeEnrichedEvent(context, mustEncodePacket(t, messageType, message))
	if err != nil {
		t.Fatal(err)
	}
	return &fakeEventReader{eventNumber: eventNumber, data: eventData}
}

// assertExtractedValues は各フィールドの抽出結果を比較する。値がないことを期待する場合は nil を指定する。
func assertExtractedValues(t *testing.T, plugin *Plugin, eventReader sdk.EventReader, expectedValues map[string]any) {
	t.Helper()
	for fieldName, expectedValue := range expectedValues {
		extractedValue := extractField(t, plugin, eventReader, fieldName)
		if fmt.Sprint(extractedValue) != fmt.Sprint(expectedValue) || (extractedValue == nil) != (expectedValue == nil) {
			t.Errorf("%s = %v (%T), want %v (%T)", fieldName, extractedValue, extractedValue, expectedValue, expectedValue)
		}
	}
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
	eventReader := newEnrichedEventReader(t, 1, processContext{}, pb.MessageType_MESSAGE_SYSCALL_OPEN, openMessage)
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
	eventReader := newEnrichedEventReader(t, 2, processContext{}, pb.MessageType_MESSAGE_SYSCALL_RAW, rawSyscallMessage)
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
	eventReader := newEnrichedEventReader(t, 3, processContext{}, pb.MessageType_MESSAGE_SENTRY_CLONE, cloneMessage)
	plugin := &Plugin{}

	if eventType := extractField(t, plugin, eventReader, "evt.type"); eventType != "sentry_clone" {
		t.Errorf("evt.type = %v, want sentry_clone", eventType)
	}
	if syscallNumber := extractField(t, plugin, eventReader, "gvisor.sysno"); syscallNumber != nil {
		t.Errorf("gvisor.sysno = %v, want no value", syscallNumber)
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

func TestDecodeEnrichedEventRejectsPacketWithoutHeader(t *testing.T) {
	packet := mustEncodePacket(t, pb.MessageType_MESSAGE_SYSCALL_OPEN, &pb.Open{})
	if _, err := decodeEnrichedEvent(packet); err == nil {
		t.Error("expected error for gVisor packet without process context header")
	}
}

func TestProcessContextIsReducedWhenTooLarge(t *testing.T) {
	hugeArgument := strings.Repeat("a", maxProcessContextBytes)
	context := processContext{
		Process:   &processInfo{PID: 2, Name: "child", Args: []string{hugeArgument}},
		Ancestors: []processInfo{{PID: 1, Name: "parent", Args: []string{hugeArgument}}},
	}
	eventReader := newEnrichedEventReader(t, 1, context, pb.MessageType_MESSAGE_SYSCALL_OPEN, &pb.Open{
		ContextData: &pb.ContextData{ThreadGroupId: 2},
	})
	if len(eventReader.data) > enrichedEventHeaderSize+maxProcessContextBytes+1024 {
		t.Fatalf("event size = %d, process context was not reduced", len(eventReader.data))
	}
	assertExtractedValues(t, &Plugin{}, eventReader, map[string]any{
		"proc.name":  "child",
		"proc.pname": "parent",
		"proc.args":  "",
	})
}
