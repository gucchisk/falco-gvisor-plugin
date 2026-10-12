package gvisor

import (
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

// recordMessage は gVisor から届いたメッセージと同じ経路 (エンコード → デコード) でプロセス表に記録する。
func recordMessage(t *testing.T, processes *processTable, messageType pb.MessageType, message proto.Message) processContext {
	t.Helper()
	event, err := decodeGVisorEvent(mustEncodePacket(t, messageType, message))
	if err != nil {
		t.Fatal(err)
	}
	return processes.recordEvent(event)
}

func contextOfProcess(processID int32, processName string) *pb.ContextData {
	return &pb.ContextData{ThreadId: processID, ThreadGroupId: processID, ProcessName: processName}
}

func TestProcessTableTracksContainerStartCloneAndExecve(t *testing.T) {
	processes := newProcessTable()

	recordMessage(t, processes, pb.MessageType_MESSAGE_CONTAINER_START, &pb.Start{
		ContextData: contextOfProcess(1, "sh"),
		Args:        []string{"/bin/sh", "-c", "/app/server"},
		Cwd:         "/app",
	})
	recordMessage(t, processes, pb.MessageType_MESSAGE_SENTRY_CLONE, &pb.CloneInfo{
		ContextData:          contextOfProcess(1, "sh"),
		CreatedThreadId:      7,
		CreatedThreadGroupId: 7,
	})
	// sentry/execve は exec 前のタスクの context で届く。
	recordMessage(t, processes, pb.MessageType_MESSAGE_SENTRY_EXEC, &pb.ExecveInfo{
		ContextData:          contextOfProcess(7, "sh"),
		BinaryPath:           "/usr/bin/curl",
		Execfn:               "/usr/bin/curl",
		Argv:                 []string{"curl", "-s", "http://example.com"},
		BinaryOverlayfsUpper: true,
		Stdin:                &pb.FdInfo{Path: "/dev/pts/3", Mode: linuxFileTypeCharDevice | 0o620},
		Stdout:               &pb.FdInfo{Mode: linuxFileTypeSocket, Socket: &pb.SocketInfo{Family: linuxAddressFamilyInet}},
		Stderr:               &pb.FdInfo{Path: "/dev/null", Mode: linuxFileTypeCharDevice | 0o666},
	})
	// syscall/execve/exit の context の process_name は exec 前の名前のことがあるが、プロセス表の名前を使う。
	execveContext := recordMessage(t, processes, pb.MessageType_MESSAGE_SYSCALL_EXECVE, &pb.Execve{
		ContextData: contextOfProcess(7, "sh"),
		Exit:        &pb.Exit{},
	})

	process := execveContext.Process
	if process == nil {
		t.Fatal("process context is empty")
	}
	expectedProcess := processInfo{
		PID: 7, ParentPID: 1, Name: "curl", ExeArgument: "curl", ExePath: "/usr/bin/curl",
		Args: []string{"-s", "http://example.com"}, Cwd: "/app",
		TerminalDevice:  encodeLinuxDeviceNumber(linuxPseudoTerminalMajor, 3),
		IsExeUpperLayer: true,
		StdinType:       "file", StdoutType: "ipv4", StderrType: "file",
	}
	if !reflect.DeepEqual(*process, expectedProcess) {
		t.Errorf("process = %+v\nwant      %+v", *process, expectedProcess)
	}
	if len(execveContext.Ancestors) != 1 {
		t.Fatalf("ancestors = %+v, want only the container init", execveContext.Ancestors)
	}
	parent := execveContext.Ancestors[0]
	if parent.PID != 1 || parent.Name != "sh" || parent.ExePath != "/bin/sh" || formatCommandLine(parent.Name, parent.Args) != "sh -c /app/server" {
		t.Errorf("parent = %+v", parent)
	}

	recordMessage(t, processes, pb.MessageType_MESSAGE_SENTRY_TASK_EXIT, &pb.TaskExit{ContextData: contextOfProcess(7, "curl")})
	if _, stillTracked := processes.processesByPID[7]; stillTracked {
		t.Error("process 7 should be removed after task exit")
	}
}

func TestProcessTableIgnoresThreadCreation(t *testing.T) {
	processes := newProcessTable()
	recordMessage(t, processes, pb.MessageType_MESSAGE_SENTRY_CLONE, &pb.CloneInfo{
		ContextData:          contextOfProcess(10, "java"),
		CreatedThreadId:      11,
		CreatedThreadGroupId: 10,
		Flags:                linuxCloneThread,
	})
	if len(processes.processesByPID) != 1 {
		t.Errorf("tracked processes = %v, want only pid 10", processes.processesByPID)
	}

	// スレッドの終了ではプロセスを消さない。
	recordMessage(t, processes, pb.MessageType_MESSAGE_SENTRY_TASK_EXIT, &pb.TaskExit{
		ContextData: &pb.ContextData{ThreadId: 11, ThreadGroupId: 10},
	})
	if _, stillTracked := processes.processesByPID[10]; !stillTracked {
		t.Error("process 10 should remain after one of its threads exits")
	}
}

func TestProcessTableCloneParentFlagUsesGrandparent(t *testing.T) {
	processes := newProcessTable()
	recordMessage(t, processes, pb.MessageType_MESSAGE_SENTRY_CLONE, &pb.CloneInfo{
		ContextData:          &pb.ContextData{ThreadId: 20, ThreadGroupId: 20, ParentThreadGroupId: 1, ProcessName: "daemon"},
		CreatedThreadGroupId: 21,
		Flags:                linuxCloneParent,
	})
	if parentPID := processes.processesByPID[21].ParentPID; parentPID != 1 {
		t.Errorf("parent of pid 21 = %d, want 1 (CLONE_PARENT)", parentPID)
	}
}

func TestProcessTableCreatesUnknownProcessFromContextFields(t *testing.T) {
	processes := newProcessTable()
	// runsc exec (kubectl exec) で作られたプロセスには clone / execve の point が届かない。
	context := recordMessage(t, processes, pb.MessageType_MESSAGE_SYSCALL_OPEN, &pb.Open{
		ContextData: &pb.ContextData{
			ThreadId: 30, ThreadGroupId: 30, ProcessName: "bash", Cwd: "/root", IsExecSession: true,
		},
	})
	process := context.Process
	if process == nil || process.Name != "bash" || process.Cwd != "/root" || !process.IsExecSession {
		t.Errorf("process = %+v", process)
	}
}

func TestProcessTableFollowsReparenting(t *testing.T) {
	processes := newProcessTable()
	recordMessage(t, processes, pb.MessageType_MESSAGE_SENTRY_CLONE, &pb.CloneInfo{
		ContextData: contextOfProcess(40, "sh"), CreatedThreadGroupId: 41,
	})
	recordMessage(t, processes, pb.MessageType_MESSAGE_SENTRY_TASK_EXIT, &pb.TaskExit{ContextData: contextOfProcess(40, "sh")})
	context := recordMessage(t, processes, pb.MessageType_MESSAGE_SYSCALL_OPEN, &pb.Open{
		ContextData: &pb.ContextData{ThreadId: 41, ThreadGroupId: 41, ParentThreadGroupId: 1},
	})
	if context.Process.ParentPID != 1 {
		t.Errorf("parent pid = %d, want 1 after the original parent exited", context.Process.ParentPID)
	}
}

func TestProcessTableLimitsAncestorDepthAndHandlesCycles(t *testing.T) {
	processes := newProcessTable()
	for processID := int64(1); processID <= maxAncestorDepth+5; processID++ {
		processes.insertProcess(&processInfo{PID: processID, ParentPID: processID - 1, Name: "p"})
	}
	deepest := processes.processesByPID[maxAncestorDepth+5]
	if ancestors := processes.snapshotProcessContext(deepest).Ancestors; len(ancestors) != maxAncestorDepth {
		t.Errorf("ancestor count = %d, want %d", len(ancestors), maxAncestorDepth)
	}

	processes.insertProcess(&processInfo{PID: 100, ParentPID: 101})
	processes.insertProcess(&processInfo{PID: 101, ParentPID: 100})
	if ancestors := processes.snapshotProcessContext(processes.processesByPID[100]).Ancestors; len(ancestors) != 1 {
		t.Errorf("ancestor count with cycle = %d, want 1", len(ancestors))
	}
}

func TestProcessTableEvictsWhenFull(t *testing.T) {
	processes := newProcessTable()
	for processID := int64(1); processID <= maxTrackedProcesses+10; processID++ {
		processes.insertProcess(&processInfo{PID: processID})
	}
	if trackedCount := len(processes.processesByPID); trackedCount != maxTrackedProcesses {
		t.Errorf("tracked processes = %d, want %d", trackedCount, maxTrackedProcesses)
	}
}

func TestLinuxTaskCommandNameIsTruncatedLikeComm(t *testing.T) {
	if commandName := linuxTaskCommandName("/usr/bin/check-new-release"); commandName != "check-new-relea" {
		t.Errorf("command name = %q, want check-new-relea", commandName)
	}
}

func TestLimitArgumentBytes(t *testing.T) {
	firstArgument := strings.Repeat("a", 4000)
	limitedArguments := limitArgumentBytes([]string{firstArgument, strings.Repeat("b", 200), "dropped"})
	// 1 つ目 (4000 バイト + 区切り 1 バイト) の残り 95 バイトに 2 つ目が切り詰められ、3 つ目は捨てられる。
	if len(limitedArguments) != 2 || len(limitedArguments[1]) != maxTrackedArgumentBytes-len(firstArgument)-1 {
		t.Errorf("limited argument count = %d, last length = %d", len(limitedArguments), len(limitedArguments[len(limitedArguments)-1]))
	}
}
