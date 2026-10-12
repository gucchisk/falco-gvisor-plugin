package gvisor

import (
	"path"
	"strings"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

// fieldExtractor はイベントからフィールドの値を取り出す。値がない場合は SetValue を呼ばない。
type fieldExtractor func(event *enrichedEvent, request sdk.ExtractRequest)

type fieldDefinition struct {
	entry   sdk.FieldEntry
	extract fieldExtractor
}

// ancestorIndexArgument は proc.aname[N] などのインデックス引数 (0 = 自分、1 = 親、2 = 祖父母 …)。
var ancestorIndexArgument = sdk.FieldEntryArg{IsRequired: true, IsIndex: true}

// fieldDefinitions はプラグインが提供するフィールド。
// Falco 標準ルールを流用できるよう、同じ意味のフィールドは Falco と同じ名前にしている。
var fieldDefinitions = []fieldDefinition{
	// --- evt.* ---
	{sdk.FieldEntry{Type: "string", Name: "evt.type", Display: "Event Type", Desc: "The name of the event (e.g. 'openat', 'execve'). For non-syscall gVisor points, the point name (e.g. 'sentry_clone', 'container_start')."},
		func(event *enrichedEvent, request sdk.ExtractRequest) {
			request.SetValue(event.GVisorEvent.EventType())
		}},
	{sdk.FieldEntry{Type: "string", Name: "evt.res", Display: "Return Value", Desc: "'SUCCESS' if the syscall succeeded, otherwise the error code name (e.g. 'ENOENT'). Only for syscall exit points."},
		func(event *enrichedEvent, request sdk.ExtractRequest) {
			if result, hasResult := event.GVisorEvent.SyscallResult(); hasResult {
				if result.Failed() {
					request.SetValue(linuxErrnoName(result.Errno))
				} else {
					request.SetValue("SUCCESS")
				}
			}
		}},
	{sdk.FieldEntry{Type: "uint64", Name: "evt.rawres", Display: "Raw Return Value", Desc: "The return value of a successful syscall (e.g. the new fd for openat/dup). No value when the syscall failed, so comparisons such as 'evt.rawres >= 0' are false for failures."},
		func(event *enrichedEvent, request sdk.ExtractRequest) {
			if result, hasResult := event.GVisorEvent.SyscallResult(); hasResult && !result.Failed() && result.ReturnValue >= 0 {
				request.SetValue(uint64(result.ReturnValue))
			}
		}},
	{sdk.FieldEntry{Type: "bool", Name: "evt.failed", Display: "Failed", Desc: "'true' if the syscall returned an error."},
		func(event *enrichedEvent, request sdk.ExtractRequest) {
			if result, hasResult := event.GVisorEvent.SyscallResult(); hasResult {
				request.SetValue(result.Failed())
			}
		}},
	{sdk.FieldEntry{Type: "bool", Name: "evt.is_open_read", Display: "Is Opened For Reading", Desc: "'true' for open/openat/openat2/creat events where the file is opened for reading."},
		func(event *enrichedEvent, request sdk.ExtractRequest) {
			if openFlags, isOpen := event.GVisorEvent.OpenFlags(); isOpen {
				request.SetValue(isLinuxOpenForRead(openFlags))
			}
		}},
	{sdk.FieldEntry{Type: "bool", Name: "evt.is_open_write", Display: "Is Opened For Writing", Desc: "'true' for open/openat/openat2/creat events where the file is opened for writing."},
		func(event *enrichedEvent, request sdk.ExtractRequest) {
			if openFlags, isOpen := event.GVisorEvent.OpenFlags(); isOpen {
				request.SetValue(isLinuxOpenForWrite(openFlags))
			}
		}},
	{sdk.FieldEntry{Type: "string", Name: "evt.arg.flags", Display: "Open Flags", Desc: "The flags of open events, formatted like Falco (e.g. 'O_WRONLY|O_CREAT|O_TRUNC')."},
		func(event *enrichedEvent, request sdk.ExtractRequest) {
			if flags, hasFlags := event.GVisorEvent.ArgumentFlags(); hasFlags {
				request.SetValue(flags)
			}
		}},
	{sdk.FieldEntry{Type: "string", Name: "evt.arg.request", Display: "Ptrace Request", Desc: "The request of ptrace events (e.g. 'PTRACE_ATTACH')."},
		func(event *enrichedEvent, request sdk.ExtractRequest) {
			if ptraceRequest, isPtrace := event.GVisorEvent.ArgumentRequest(); isPtrace {
				request.SetValue(ptraceRequest)
			}
		}},
	{sdk.FieldEntry{Type: "string", Name: "evt.arg.domain", Display: "Socket Domain", Desc: "The domain of socket events (e.g. 'AF_INET', 'AF_PACKET')."},
		func(event *enrichedEvent, request sdk.ExtractRequest) {
			if socketDomain, isSocket := event.GVisorEvent.ArgumentDomain(); isSocket {
				request.SetValue(socketDomain)
			}
		}},

	// --- fd.* ---
	{sdk.FieldEntry{Type: "uint64", Name: "fd.num", Display: "FD Number", Desc: "The file descriptor number. For open events, only when the open succeeded."},
		extractFileDescriptorField(func(fileDescriptor fileDescriptorInfo, request sdk.ExtractRequest) {
			if fileDescriptor.HasNumber && fileDescriptor.Number >= 0 {
				request.SetValue(uint64(fileDescriptor.Number))
			}
		})},
	{sdk.FieldEntry{Type: "string", Name: "fd.name", Display: "FD Name", Desc: "The absolute path for file events, 'IP:port' of the remote peer for inet connect events, or the socket path for unix connect events. Relative paths need the 'cwd' context field (or the 'fd_path' optional field for dirfd)."},
		extractFileDescriptorField(func(fileDescriptor fileDescriptorInfo, request sdk.ExtractRequest) {
			if fileDescriptor.Name != "" {
				request.SetValue(fileDescriptor.Name)
			}
		})},
	{sdk.FieldEntry{Type: "string", Name: "fd.nameraw", Display: "FD Name Raw", Desc: "The path exactly as passed to the syscall (not normalized)."},
		extractFileDescriptorField(func(fileDescriptor fileDescriptorInfo, request sdk.ExtractRequest) {
			if fileDescriptor.RawName != "" {
				request.SetValue(fileDescriptor.RawName)
			}
		})},
	{sdk.FieldEntry{Type: "string", Name: "fd.directory", Display: "FD Directory", Desc: "The directory part of fd.name for file events."},
		extractFileDescriptorField(func(fileDescriptor fileDescriptorInfo, request sdk.ExtractRequest) {
			if fileDescriptor.IsFile() && path.IsAbs(fileDescriptor.Name) {
				request.SetValue(path.Dir(fileDescriptor.Name))
			}
		})},
	{sdk.FieldEntry{Type: "string", Name: "fd.filename", Display: "FD File Name", Desc: "The file name part of fd.name for file events."},
		extractFileDescriptorField(func(fileDescriptor fileDescriptorInfo, request sdk.ExtractRequest) {
			if fileDescriptor.IsFile() && fileDescriptor.Name != "" {
				request.SetValue(path.Base(fileDescriptor.Name))
			}
		})},
	{sdk.FieldEntry{Type: "string", Name: "fd.type", Display: "FD Type", Desc: "The type of the file descriptor: 'file', 'directory', 'ipv4', 'ipv6', 'unix', 'netlink' or 'socket'."},
		extractFileDescriptorField(func(fileDescriptor fileDescriptorInfo, request sdk.ExtractRequest) {
			if fileDescriptor.Type != "" {
				request.SetValue(fileDescriptor.Type)
			}
		})},
	{sdk.FieldEntry{Type: "string", Name: "fd.typechar", Display: "FD Type Char", Desc: "The type of the file descriptor as a single character: 'f' (file), 'd' (directory), '4' (ipv4), '6' (ipv6), 'u' (unix), 'n' (netlink)."},
		extractFileDescriptorField(func(fileDescriptor fileDescriptorInfo, request sdk.ExtractRequest) {
			if typeChar := fileDescriptor.TypeChar(); typeChar != "" {
				request.SetValue(typeChar)
			}
		})},
	{sdk.FieldEntry{Type: "ipaddr", Name: "fd.sip", Display: "Server IP", Desc: "The server (= remote peer) IP address of inet connect events."},
		extractFileDescriptorField(extractRemoteIP)},
	{sdk.FieldEntry{Type: "ipaddr", Name: "fd.rip", Display: "Remote IP", Desc: "The remote IP address of inet connect events."},
		extractFileDescriptorField(extractRemoteIP)},
	{sdk.FieldEntry{Type: "uint64", Name: "fd.sport", Display: "Server Port", Desc: "The server (= remote peer) port of inet connect events."},
		extractFileDescriptorField(extractRemotePort)},
	{sdk.FieldEntry{Type: "uint64", Name: "fd.rport", Display: "Remote Port", Desc: "The remote port of inet connect events."},
		extractFileDescriptorField(extractRemotePort)},

	// --- proc.* / thread.* / user.* / group.* ---
	{sdk.FieldEntry{Type: "uint64", Name: "proc.pid", Display: "Process ID", Desc: "The PID (thread group ID) inside the sandbox. Requires the 'group_id' context field."},
		func(event *enrichedEvent, request sdk.ExtractRequest) {
			if processID := event.GVisorEvent.ContextData.GetThreadGroupId(); processID != 0 {
				request.SetValue(uint64(processID))
			}
		}},
	{sdk.FieldEntry{Type: "string", Name: "proc.name", Display: "Process Name", Desc: "The name (excluding the path, truncated to 15 characters) of the executable generating the event. For execve events, the name after exec (requires the sentry/execve point)."},
		func(event *enrichedEvent, request sdk.ExtractRequest) {
			if processName := event.ProcessName(); processName != "" {
				request.SetValue(processName)
			}
		}},
	{sdk.FieldEntry{Type: "string", Name: "proc.exe", Display: "Executable", Desc: "The first command line argument (argv[0]). Requires the sentry/execve point."},
		extractProcessField(func(process *processInfo, request sdk.ExtractRequest) {
			if process.ExeArgument != "" {
				request.SetValue(process.ExeArgument)
			}
		})},
	{sdk.FieldEntry{Type: "string", Name: "proc.exepath", Display: "Executable Path", Desc: "The full path of the executable. Requires the sentry/execve point."},
		extractProcessField(func(process *processInfo, request sdk.ExtractRequest) {
			if process.ExePath != "" {
				request.SetValue(process.ExePath)
			}
		})},
	{sdk.FieldEntry{Type: "string", Name: "proc.args", Display: "Arguments", Desc: "The arguments passed on the command line (excluding argv[0]), joined by spaces."},
		extractProcessField(func(process *processInfo, request sdk.ExtractRequest) {
			request.SetValue(strings.Join(process.Args, " "))
		})},
	{sdk.FieldEntry{Type: "string", Name: "proc.cmdline", Display: "Command Line", Desc: "The full command line, i.e. proc.name + proc.args."},
		func(event *enrichedEvent, request sdk.ExtractRequest) {
			if process := event.ProcessContext.Process; process != nil {
				request.SetValue(formatCommandLine(event.ProcessName(), process.Args))
			}
		}},
	{sdk.FieldEntry{Type: "string", Name: "proc.cwd", Display: "Current Working Directory", Desc: "The current working directory of the process. Requires the 'cwd' context field."},
		func(event *enrichedEvent, request sdk.ExtractRequest) {
			if cwd := event.CurrentWorkingDirectory(); cwd != "" {
				request.SetValue(cwd)
			}
		}},
	{sdk.FieldEntry{Type: "uint64", Name: "proc.tty", Display: "TTY", Desc: "Approximation of the controlling terminal: the device number of the first standard stream that is /dev/pts/N or /dev/ttyN at exec time (0 if none). Requires the 'fd_info' optional field of sentry/execve."},
		extractProcessField(func(process *processInfo, request sdk.ExtractRequest) {
			request.SetValue(process.TerminalDevice)
		})},
	{sdk.FieldEntry{Type: "bool", Name: "proc.is_exe_upper_layer", Display: "Executable Is In Upper Layer", Desc: "'true' if the executable is in the writable (upper) layer of the container overlay, i.e. not part of the image. Requires the 'binary_info' optional field of sentry/execve."},
		extractProcessField(func(process *processInfo, request sdk.ExtractRequest) {
			request.SetValue(process.IsExeUpperLayer)
		})},
	{sdk.FieldEntry{Type: "bool", Name: "proc.is_exe_from_memfd", Display: "Executable Is From Memfd", Desc: "'true' if the executable was run from a memfd (fileless execution). Requires the 'binary_info' optional field of sentry/execve."},
		extractProcessField(func(process *processInfo, request sdk.ExtractRequest) {
			request.SetValue(process.IsExeFromMemfd)
		})},
	{sdk.FieldEntry{Type: "string", Name: "proc.stdin.type", Display: "Stdin Type", Desc: "The fd.type of stdin at exec time. Requires the 'fd_info' optional field of sentry/execve."},
		extractProcessField(func(process *processInfo, request sdk.ExtractRequest) {
			if process.StdinType != "" {
				request.SetValue(process.StdinType)
			}
		})},
	{sdk.FieldEntry{Type: "string", Name: "proc.stdout.type", Display: "Stdout Type", Desc: "The fd.type of stdout at exec time. Requires the 'fd_info' optional field of sentry/execve."},
		extractProcessField(func(process *processInfo, request sdk.ExtractRequest) {
			if process.StdoutType != "" {
				request.SetValue(process.StdoutType)
			}
		})},
	{sdk.FieldEntry{Type: "string", Name: "proc.stderr.type", Display: "Stderr Type", Desc: "The fd.type of stderr at exec time. Requires the 'fd_info' optional field of sentry/execve."},
		extractProcessField(func(process *processInfo, request sdk.ExtractRequest) {
			if process.StderrType != "" {
				request.SetValue(process.StderrType)
			}
		})},
	{sdk.FieldEntry{Type: "uint64", Name: "proc.ppid", Display: "Parent Process ID", Desc: "The PID of the parent process."},
		extractAncestorField(1, func(ancestor *processInfo, request sdk.ExtractRequest) {
			request.SetValue(uint64(ancestor.PID))
		})},
	{sdk.FieldEntry{Type: "string", Name: "proc.pname", Display: "Parent Name", Desc: "The name of the parent process."},
		extractAncestorField(1, extractAncestorName)},
	{sdk.FieldEntry{Type: "string", Name: "proc.pexe", Display: "Parent Executable", Desc: "argv[0] of the parent process."},
		extractAncestorField(1, func(ancestor *processInfo, request sdk.ExtractRequest) {
			if ancestor.ExeArgument != "" {
				request.SetValue(ancestor.ExeArgument)
			}
		})},
	{sdk.FieldEntry{Type: "string", Name: "proc.pexepath", Display: "Parent Executable Path", Desc: "The full executable path of the parent process."},
		extractAncestorField(1, extractAncestorExePath)},
	{sdk.FieldEntry{Type: "string", Name: "proc.pcmdline", Display: "Parent Command Line", Desc: "The full command line of the parent process."},
		extractAncestorField(1, func(ancestor *processInfo, request sdk.ExtractRequest) {
			request.SetValue(formatCommandLine(ancestor.Name, ancestor.Args))
		})},
	{sdk.FieldEntry{Type: "string", Name: "proc.aname", Arg: ancestorIndexArgument, Display: "Ancestor Name", Desc: "The name of an ancestor: proc.aname[1] is the parent, proc.aname[2] the grandparent, and so on (proc.aname[0] is the process itself). The index is required; to match any ancestor use gvisor.anames."},
		extractIndexedAncestorField(extractAncestorName)},
	{sdk.FieldEntry{Type: "uint64", Name: "proc.apid", Arg: ancestorIndexArgument, Display: "Ancestor PID", Desc: "The PID of an ancestor (same indexing as proc.aname)."},
		extractIndexedAncestorField(func(ancestor *processInfo, request sdk.ExtractRequest) {
			request.SetValue(uint64(ancestor.PID))
		})},
	{sdk.FieldEntry{Type: "string", Name: "proc.aexepath", Arg: ancestorIndexArgument, Display: "Ancestor Executable Path", Desc: "The full executable path of an ancestor (same indexing as proc.aname)."},
		extractIndexedAncestorField(extractAncestorExePath)},
	{sdk.FieldEntry{Type: "uint64", Name: "thread.tid", Display: "Thread ID", Desc: "The thread ID inside the sandbox. Requires the 'thread_id' context field."},
		func(event *enrichedEvent, request sdk.ExtractRequest) {
			if threadID := event.GVisorEvent.ContextData.GetThreadId(); threadID != 0 {
				request.SetValue(uint64(threadID))
			}
		}},
	{sdk.FieldEntry{Type: "uint64", Name: "user.uid", Display: "User ID", Desc: "The effective user ID. Requires the 'credentials' context field."},
		func(event *enrichedEvent, request sdk.ExtractRequest) {
			if credentials := event.GVisorEvent.ContextData.GetCredentials(); credentials != nil {
				request.SetValue(uint64(credentials.GetEffectiveUid()))
			}
		}},
	{sdk.FieldEntry{Type: "uint64", Name: "group.gid", Display: "Group ID", Desc: "The effective group ID. Requires the 'credentials' context field."},
		func(event *enrichedEvent, request sdk.ExtractRequest) {
			if credentials := event.GVisorEvent.ContextData.GetCredentials(); credentials != nil {
				request.SetValue(uint64(credentials.GetEffectiveGid()))
			}
		}},

	// --- gvisor.* (Falco に同等のフィールドがないもの) ---
	{sdk.FieldEntry{Type: "string", Name: "gvisor.anames", IsList: true, Display: "Ancestor Names", Desc: "The names of all ancestors (parent first). Use 'gvisor.anames intersects (a, b)' in place of Falco's 'proc.aname in (a, b)'."},
		func(event *enrichedEvent, request sdk.ExtractRequest) {
			ancestorNames := make([]string, 0, len(event.ProcessContext.Ancestors))
			for _, ancestor := range event.ProcessContext.Ancestors {
				ancestorNames = append(ancestorNames, ancestor.Name)
			}
			request.SetValue(ancestorNames)
		}},
	{sdk.FieldEntry{Type: "bool", Name: "gvisor.is_exec_session", Display: "Is Exec Session", Desc: "'true' if the process was created by 'runsc exec' (e.g. kubectl exec). Requires the 'is_exec_session' context field."},
		func(event *enrichedEvent, request sdk.ExtractRequest) {
			if process := event.ProcessContext.Process; process != nil {
				request.SetValue(process.IsExecSession)
			}
		}},
	{sdk.FieldEntry{Type: "uint64", Name: "gvisor.sysno", Display: "Syscall Number", Desc: "The raw syscall number reported by gVisor."},
		func(event *enrichedEvent, request sdk.ExtractRequest) {
			if event.GVisorEvent.HasSyscall {
				request.SetValue(event.GVisorEvent.SyscallNumber)
			}
		}},
	{sdk.FieldEntry{Type: "string", Name: "gvisor.container_id", Display: "Container ID", Desc: "The container ID reported by gVisor. Requires the 'container_id' context field."},
		func(event *enrichedEvent, request sdk.ExtractRequest) {
			request.SetValue(event.GVisorEvent.ContextData.GetContainerId())
		}},
	{sdk.FieldEntry{Type: "uint64", Name: "gvisor.pid", Display: "Process ID", Desc: "Same as proc.pid (kept for compatibility)."},
		func(event *enrichedEvent, request sdk.ExtractRequest) {
			request.SetValue(uint64(event.GVisorEvent.ContextData.GetThreadGroupId()))
		}},
	{sdk.FieldEntry{Type: "uint64", Name: "gvisor.tid", Display: "Thread ID", Desc: "Same as thread.tid (kept for compatibility)."},
		func(event *enrichedEvent, request sdk.ExtractRequest) {
			request.SetValue(uint64(event.GVisorEvent.ContextData.GetThreadId()))
		}},
}

// fieldExtractorsByName はフィールド名から抽出関数を引くための索引。
var fieldExtractorsByName = func() map[string]fieldExtractor {
	extractorsByName := make(map[string]fieldExtractor, len(fieldDefinitions))
	for _, definition := range fieldDefinitions {
		extractorsByName[definition.entry.Name] = definition.extract
	}
	return extractorsByName
}()

// ProcessName は Falco の proc.name に相当する値を返す。
// プロセス表の名前 (execve 後の名前) を優先し、なければ context field の process_name を使う。
func (event *enrichedEvent) ProcessName() string {
	if process := event.ProcessContext.Process; process != nil && process.Name != "" {
		return process.Name
	}
	return event.GVisorEvent.ProcessName()
}

// CurrentWorkingDirectory はイベント発生時のカレントディレクトリを返す。
func (event *enrichedEvent) CurrentWorkingDirectory() string {
	if cwd := event.GVisorEvent.ContextData.GetCwd(); cwd != "" {
		return cwd
	}
	if process := event.ProcessContext.Process; process != nil {
		return process.Cwd
	}
	return ""
}

// ancestor は depth 番目の祖先を返す (0 = 自分、1 = 親 …)。
func (event *enrichedEvent) ancestor(depth uint64) *processInfo {
	if depth == 0 {
		if process := event.ProcessContext.Process; process != nil {
			processWithResolvedName := *process
			processWithResolvedName.Name = event.ProcessName()
			return &processWithResolvedName
		}
		return nil
	}
	if depth > uint64(len(event.ProcessContext.Ancestors)) {
		return nil
	}
	return &event.ProcessContext.Ancestors[depth-1]
}

func extractFileDescriptorField(extract func(fileDescriptor fileDescriptorInfo, request sdk.ExtractRequest)) fieldExtractor {
	return func(event *enrichedEvent, request sdk.ExtractRequest) {
		if fileDescriptor, hasFileDescriptor := event.GVisorEvent.FileDescriptor(event.CurrentWorkingDirectory()); hasFileDescriptor {
			extract(fileDescriptor, request)
		}
	}
}

func extractProcessField(extract func(process *processInfo, request sdk.ExtractRequest)) fieldExtractor {
	return func(event *enrichedEvent, request sdk.ExtractRequest) {
		if process := event.ProcessContext.Process; process != nil {
			extract(process, request)
		}
	}
}

func extractAncestorField(depth uint64, extract func(ancestor *processInfo, request sdk.ExtractRequest)) fieldExtractor {
	return func(event *enrichedEvent, request sdk.ExtractRequest) {
		if ancestor := event.ancestor(depth); ancestor != nil {
			extract(ancestor, request)
		}
	}
}

func extractIndexedAncestorField(extract func(ancestor *processInfo, request sdk.ExtractRequest)) fieldExtractor {
	return func(event *enrichedEvent, request sdk.ExtractRequest) {
		if ancestor := event.ancestor(request.ArgIndex()); ancestor != nil {
			extract(ancestor, request)
		}
	}
}

func extractAncestorName(ancestor *processInfo, request sdk.ExtractRequest) {
	if ancestor.Name != "" {
		request.SetValue(ancestor.Name)
	}
}

func extractAncestorExePath(ancestor *processInfo, request sdk.ExtractRequest) {
	if ancestor.ExePath != "" {
		request.SetValue(ancestor.ExePath)
	}
}

func extractRemoteIP(fileDescriptor fileDescriptorInfo, request sdk.ExtractRequest) {
	if fileDescriptor.RemoteIP != nil {
		request.SetValue(fileDescriptor.RemoteIP)
	}
}

func extractRemotePort(fileDescriptor fileDescriptorInfo, request sdk.ExtractRequest) {
	if fileDescriptor.RemoteIP != nil {
		request.SetValue(uint64(fileDescriptor.RemotePort))
	}
}

// formatCommandLine は Falco の proc.cmdline と同じく「名前 + 空白 + 引数」の形式にする。
func formatCommandLine(processName string, arguments []string) string {
	if len(arguments) == 0 {
		return processName
	}
	return processName + " " + strings.Join(arguments, " ")
}
