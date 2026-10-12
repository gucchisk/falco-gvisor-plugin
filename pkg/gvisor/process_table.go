package gvisor

import (
	"path"
	"strconv"
	"strings"

	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

const (
	// maxTrackedProcesses はプロセス表に保持するプロセス数の上限。
	// sentry/task_exit を取りこぼしてもメモリが際限なく増えないようにする。
	maxTrackedProcesses = 32768
	// maxAncestorDepth は proc.aname[N] などで辿れる祖先の深さの上限。
	maxAncestorDepth = 16
	// maxTrackedArgumentBytes は 1 プロセスあたりに保持するコマンドライン引数の合計バイト数の上限。
	maxTrackedArgumentBytes = 4096
	// linuxTaskCommandMaxLength は Linux の comm (TASK_COMM_LEN - 1)。Falco の proc.name も同じ長さで切り詰められる。
	linuxTaskCommandMaxLength = 15

	linuxCloneThread = 0x10000
	linuxCloneParent = 0x8000

	linuxPseudoTerminalMajor = 136 // /dev/pts/N
	linuxVirtualConsoleMajor = 4   // /dev/ttyN
)

// processInfo はスレッドグループ (= プロセス) ごとの情報。
// プロセス表のエントリであり、Falco に送るイベントに埋め込むスナップショットでもある。
type processInfo struct {
	PID       int64 `json:"pid"`
	ParentPID int64 `json:"ppid,omitempty"`
	// Name は Falco の proc.name に相当する (実行ファイル名を 15 文字で切り詰めたもの)。
	Name string `json:"name,omitempty"`
	// ExeArgument は Falco の proc.exe に相当する (argv[0])。
	ExeArgument string `json:"exe,omitempty"`
	// ExePath は Falco の proc.exepath に相当する (実行ファイルのフルパス)。
	ExePath string   `json:"exepath,omitempty"`
	Args    []string `json:"args,omitempty"`
	Cwd     string   `json:"cwd,omitempty"`
	// TerminalDevice は Falco の proc.tty に相当する端末のデバイス番号。端末がなければ 0。
	TerminalDevice  uint64 `json:"tty,omitempty"`
	IsExeUpperLayer bool   `json:"exe_upper_layer,omitempty"`
	IsExeFromMemfd  bool   `json:"exe_from_memfd,omitempty"`
	IsExecSession   bool   `json:"exec_session,omitempty"`
	StdinType       string `json:"stdin_type,omitempty"`
	StdoutType      string `json:"stdout_type,omitempty"`
	StderrType      string `json:"stderr_type,omitempty"`
}

// processContext はイベントを発生させたプロセスと、その祖先のスナップショット。
// 受信時点のプロセス表から作ってイベントデータに埋め込むため、
// Falco のキャプチャファイルを再生しても同じ値が得られる。
type processContext struct {
	Process *processInfo `json:"process,omitempty"`
	// Ancestors は親 (Ancestors[0])、祖父母 (Ancestors[1]) … の順に並ぶ。
	// 親以外は引数を持たない (proc.aname[N] などは名前とパスしか使わないため)。
	Ancestors []processInfo `json:"ancestors,omitempty"`
}

// processTable は 1 つのサンドボックス (gVisor との 1 接続) 内のプロセスを PID ごとに管理する。
// PID はサンドボックスごとに独立しているため、接続ごとに別の表を使う。
// 1 つの接続の goroutine からしか使わないので排他制御はしない。
type processTable struct {
	processesByPID map[int64]*processInfo
}

func newProcessTable() *processTable {
	return &processTable{processesByPID: make(map[int64]*processInfo)}
}

// recordEvent はイベントの内容でプロセス表を更新し、イベント発生時点のプロセス情報を返す。
//
// 更新に使う trace point:
//   - container/start: コンテナの最初のプロセス
//   - sentry/clone: 子プロセスの作成 (親の情報を引き継ぐ)
//   - sentry/execve: 実行ファイル・引数の更新 (syscall/execve/exit より先に届く)
//   - sentry/task_exit: プロセスの終了
//
// これらが届かないプロセス (runsc exec で作られたものなど) は、
// 最初のイベントの context field から作成する。
func (table *processTable) recordEvent(event *gVisorEvent) processContext {
	contextData := event.ContextData
	processID := int64(contextData.GetThreadGroupId())
	if processID == 0 {
		// group_id の context field がないとプロセスを特定できない。
		return processContext{}
	}

	process := table.findOrCreateProcess(processID, contextData)
	updateProcessFromContextData(process, contextData)

	switch message := event.Message.(type) {
	case *pb.Start:
		updateProcessFromContainerStart(process, message)
	case *pb.CloneInfo:
		table.recordClone(process, message)
	case *pb.ExecveInfo:
		updateProcessFromExecve(process, message)
	}

	snapshot := table.snapshotProcessContext(process)

	if taskExit, isTaskExit := event.Message.(*pb.TaskExit); isTaskExit {
		exitedThreadID := int64(taskExit.GetContextData().GetThreadId())
		if exitedThreadID == processID {
			// スレッドグループリーダーの終了をプロセスの終了とみなす。
			delete(table.processesByPID, processID)
		}
	}
	return snapshot
}

func (table *processTable) findOrCreateProcess(processID int64, contextData *pb.ContextData) *processInfo {
	if process, found := table.processesByPID[processID]; found {
		return process
	}
	process := &processInfo{
		PID:  processID,
		Name: contextData.GetProcessName(),
	}
	table.insertProcess(process)
	return process
}

func (table *processTable) insertProcess(process *processInfo) {
	if _, alreadyTracked := table.processesByPID[process.PID]; !alreadyTracked && len(table.processesByPID) >= maxTrackedProcesses {
		// 上限に達したら任意の 1 件を捨てる (Go の map の反復順は不定なので実質ランダム)。
		for evictedPID := range table.processesByPID {
			delete(table.processesByPID, evictedPID)
			break
		}
	}
	table.processesByPID[process.PID] = process
}

// updateProcessFromContextData は全イベントに付く context field から最新の値を反映する。
func updateProcessFromContextData(process *processInfo, contextData *pb.ContextData) {
	if contextData == nil {
		return
	}
	if cwd := contextData.GetCwd(); cwd != "" {
		process.Cwd = cwd
	}
	// 親が終了して init などに付け替えられた場合も、parent_thread_group_id で追従できる。
	if parentPID := contextData.GetParentThreadGroupId(); parentPID != 0 {
		process.ParentPID = int64(parentPID)
	}
	if contextData.GetIsExecSession() {
		process.IsExecSession = true
	}
	if process.Name == "" {
		process.Name = contextData.GetProcessName()
	}
}

func updateProcessFromContainerStart(process *processInfo, start *pb.Start) {
	if len(start.GetArgs()) > 0 {
		executable := start.GetArgs()[0]
		process.ExeArgument = executable
		process.ExePath = executable
		process.Name = linuxTaskCommandName(executable)
		process.Args = limitArgumentBytes(start.GetArgs()[1:])
	}
	if process.Cwd == "" {
		process.Cwd = start.GetCwd()
	}
	if start.GetTerminal() && process.TerminalDevice == 0 {
		// OCI spec で terminal: true のコンテナ。端末番号は分からないので /dev/pts/0 とみなす。
		process.TerminalDevice = encodeLinuxDeviceNumber(linuxPseudoTerminalMajor, 0)
	}
}

func (table *processTable) recordClone(parentProcess *processInfo, clone *pb.CloneInfo) {
	childPID := int64(clone.GetCreatedThreadGroupId())
	if clone.GetFlags()&linuxCloneThread != 0 || childPID == 0 || childPID == parentProcess.PID {
		return // スレッドの作成ではプロセスは増えない
	}
	childProcess := *parentProcess
	childProcess.PID = childPID
	childProcess.ParentPID = parentProcess.PID
	if clone.GetFlags()&linuxCloneParent != 0 {
		childProcess.ParentPID = parentProcess.ParentPID
	}
	childProcess.Args = append([]string(nil), parentProcess.Args...)
	table.insertProcess(&childProcess)
}

func updateProcessFromExecve(process *processInfo, execve *pb.ExecveInfo) {
	process.ExePath = execve.GetBinaryPath()
	process.ExeArgument = ""
	process.Args = nil
	if argv := execve.GetArgv(); len(argv) > 0 {
		process.ExeArgument = argv[0]
		process.Args = limitArgumentBytes(argv[1:])
	}
	// Linux の comm は execve に渡したファイル名の basename になる。
	executedFileName := execve.GetExecfn()
	if executedFileName == "" {
		executedFileName = execve.GetBinaryPath()
	}
	if executedFileName != "" {
		process.Name = linuxTaskCommandName(executedFileName)
	}
	// binary_info の optional field が無効なら常に false になる。
	process.IsExeUpperLayer = execve.GetBinaryOverlayfsUpper()
	process.IsExeFromMemfd = execve.GetBinaryInMemfd()

	// fd_info の optional field が有効な場合だけ標準入出力の情報が届く。
	// 届かない場合は fork 元から引き継いだ値のままにする。
	if execve.GetStdin() != nil || execve.GetStdout() != nil || execve.GetStderr() != nil {
		process.StdinType = describeFileDescriptorType(execve.GetStdin())
		process.StdoutType = describeFileDescriptorType(execve.GetStdout())
		process.StderrType = describeFileDescriptorType(execve.GetStderr())
		process.TerminalDevice = terminalDeviceFromStandardStreams(execve.GetStdin(), execve.GetStdout(), execve.GetStderr())
	}
}

// snapshotProcessContext はプロセスと祖先の情報をコピーする。
func (table *processTable) snapshotProcessContext(process *processInfo) processContext {
	processCopy := *process
	snapshot := processContext{Process: &processCopy}

	visitedPIDs := map[int64]bool{process.PID: true}
	parentPID := process.ParentPID
	for len(snapshot.Ancestors) < maxAncestorDepth && parentPID != 0 && !visitedPIDs[parentPID] {
		ancestor, found := table.processesByPID[parentPID]
		if !found {
			break
		}
		visitedPIDs[parentPID] = true
		ancestorCopy := processInfo{
			PID:         ancestor.PID,
			ParentPID:   ancestor.ParentPID,
			Name:        ancestor.Name,
			ExeArgument: ancestor.ExeArgument,
			ExePath:     ancestor.ExePath,
		}
		if len(snapshot.Ancestors) == 0 {
			ancestorCopy.Args = ancestor.Args // proc.pcmdline 用に親だけ引数を持つ
		}
		snapshot.Ancestors = append(snapshot.Ancestors, ancestorCopy)
		parentPID = ancestor.ParentPID
	}
	return snapshot
}

// linuxTaskCommandName は実行ファイルのパスから Linux の comm と同じ名前を作る。
func linuxTaskCommandName(executablePath string) string {
	commandName := path.Base(executablePath)
	if len(commandName) > linuxTaskCommandMaxLength {
		commandName = commandName[:linuxTaskCommandMaxLength]
	}
	return commandName
}

// limitArgumentBytes は引数の合計サイズが maxTrackedArgumentBytes を超えないように切り詰める。
func limitArgumentBytes(arguments []string) []string {
	limitedArguments := make([]string, 0, len(arguments))
	remainingBytes := maxTrackedArgumentBytes
	for _, argument := range arguments {
		if remainingBytes <= 0 {
			break
		}
		if len(argument) > remainingBytes {
			argument = argument[:remainingBytes]
		}
		limitedArguments = append(limitedArguments, argument)
		remainingBytes -= len(argument) + 1
	}
	return limitedArguments
}

// describeFileDescriptorType は Falco の fd.type と同じ表記でファイルディスクリプタの種類を返す。
func describeFileDescriptorType(fileDescriptor *pb.FdInfo) string {
	if fileDescriptor == nil {
		return ""
	}
	if socket := fileDescriptor.GetSocket(); socket != nil {
		return socketFamilyToFileDescriptorType(int64(socket.GetFamily()))
	}
	switch fileDescriptor.GetMode() & linuxFileTypeMask {
	case linuxFileTypeSocket:
		return "socket"
	case linuxFileTypeNamedPipe:
		return "pipe"
	case linuxFileTypeDirectory:
		return "directory"
	default:
		return "file"
	}
}

func socketFamilyToFileDescriptorType(family int64) string {
	switch family {
	case linuxAddressFamilyInet:
		return "ipv4"
	case linuxAddressFamilyInet6:
		return "ipv6"
	case linuxAddressFamilyUnix:
		return "unix"
	case linuxAddressFamilyNetlink:
		return "netlink"
	default:
		return "socket"
	}
}

// terminalDeviceFromStandardStreams は標準入出力のどれかが端末なら、そのデバイス番号を返す。
// gVisor は制御端末を送らないため、標準入出力のパスから推定する近似値。
func terminalDeviceFromStandardStreams(standardStreams ...*pb.FdInfo) uint64 {
	for _, stream := range standardStreams {
		if stream == nil || stream.GetMode()&linuxFileTypeMask != linuxFileTypeCharDevice {
			continue
		}
		if terminalDevice := terminalDeviceFromPath(stream.GetPath()); terminalDevice != 0 {
			return terminalDevice
		}
	}
	return 0
}

func terminalDeviceFromPath(devicePath string) uint64 {
	if terminalIndex, isPseudoTerminal := strings.CutPrefix(devicePath, "/dev/pts/"); isPseudoTerminal {
		if minor, err := strconv.ParseUint(terminalIndex, 10, 32); err == nil {
			return encodeLinuxDeviceNumber(linuxPseudoTerminalMajor, minor)
		}
	}
	if terminalIndex, isVirtualConsole := strings.CutPrefix(devicePath, "/dev/tty"); isVirtualConsole {
		if minor, err := strconv.ParseUint(terminalIndex, 10, 32); err == nil {
			return encodeLinuxDeviceNumber(linuxVirtualConsoleMajor, minor)
		}
	}
	return 0
}

// encodeLinuxDeviceNumber は Linux の new_encode_dev と同じ形式でデバイス番号を作る。
// Falco の proc.tty もこの形式 (例: /dev/pts/0 = 34816)。
func encodeLinuxDeviceNumber(major, minor uint64) uint64 {
	return (minor & 0xff) | (major << 8) | ((minor &^ 0xff) << 12)
}
