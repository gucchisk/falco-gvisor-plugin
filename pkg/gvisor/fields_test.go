package gvisor

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

func extractIndexedField(t *testing.T, plugin *Plugin, eventReader sdk.EventReader, fieldName string, argumentIndex uint64) any {
	t.Helper()
	request := &fakeExtractRequest{fieldName: fieldName, argumentIndex: argumentIndex}
	if err := plugin.Extract(request, eventReader); err != nil {
		t.Fatalf("Extract(%s[%d]): %v", fieldName, argumentIndex, err)
	}
	return request.extractedValue
}

func TestFieldDefinitionsAreUniqueAndValid(t *testing.T) {
	validTypes := map[string]bool{"string": true, "uint64": true, "bool": true, "ipaddr": true}
	seenNames := map[string]bool{}
	for _, fieldEntry := range (&Plugin{}).Fields() {
		if seenNames[fieldEntry.Name] {
			t.Errorf("duplicate field %s", fieldEntry.Name)
		}
		seenNames[fieldEntry.Name] = true
		if !validTypes[fieldEntry.Type] {
			t.Errorf("field %s has unsupported type %s", fieldEntry.Name, fieldEntry.Type)
		}
	}
}

func TestExtractSuccessfulOpenatWithRelativePath(t *testing.T) {
	eventReader := newEnrichedEventReader(t, 1, processContext{}, pb.MessageType_MESSAGE_SYSCALL_OPEN, &pb.Open{
		ContextData: &pb.ContextData{ThreadGroupId: 5, Cwd: "/var/log"},
		Sysno:       openatSyscallNumber(t),
		Fd:          linuxAtCurrentWorkingDirectory,
		Pathname:    "../log/./syslog",
		Flags:       linuxOpenWriteOnly | linuxOpenCreate | linuxOpenTruncate | linuxOpenCloseOnExec,
		Exit:        &pb.Exit{Result: 3},
	})
	assertExtractedValues(t, &Plugin{}, eventReader, map[string]any{
		"evt.type":          "openat",
		"evt.res":           "SUCCESS",
		"evt.rawres":        uint64(3),
		"evt.failed":        false,
		"evt.is_open_read":  false,
		"evt.is_open_write": true,
		"evt.arg.flags":     "O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC",
		"fd.num":            uint64(3),
		"fd.name":           "/var/log/syslog",
		"fd.nameraw":        "../log/./syslog",
		"fd.directory":      "/var/log",
		"fd.filename":       "syslog",
		"fd.type":           "file",
		"fd.typechar":       "f",
		"proc.cwd":          "/var/log",
	})
}

func TestExtractFailedOpenHasNoReturnValueOrFdNumber(t *testing.T) {
	eventReader := newEnrichedEventReader(t, 1, processContext{}, pb.MessageType_MESSAGE_SYSCALL_OPEN, &pb.Open{
		Sysno:    openatSyscallNumber(t),
		Fd:       linuxAtCurrentWorkingDirectory,
		Pathname: "/etc/shadow",
		Exit:     &pb.Exit{Result: -2, Errorno: 2},
	})
	assertExtractedValues(t, &Plugin{}, eventReader, map[string]any{
		"evt.res":          "ENOENT",
		"evt.failed":       true,
		"evt.rawres":       nil,
		"fd.num":           nil,
		"fd.name":          "/etc/shadow",
		"evt.is_open_read": true,
		"evt.arg.flags":    "O_RDONLY",
	})
}

func TestExtractOpenatResolvesPathFromDirectoryFd(t *testing.T) {
	eventReader := newEnrichedEventReader(t, 1, processContext{}, pb.MessageType_MESSAGE_SYSCALL_OPEN, &pb.Open{
		ContextData: &pb.ContextData{Cwd: "/"},
		Fd:          4,
		FdPath:      "/root/.ssh",
		Pathname:    "id_rsa",
	})
	assertExtractedValues(t, &Plugin{}, eventReader, map[string]any{"fd.name": "/root/.ssh/id_rsa"})
}

func inetSocketAddress(ip net.IP, port uint16) []byte {
	socketAddress := make([]byte, 16)
	binary.LittleEndian.PutUint16(socketAddress[0:2], linuxAddressFamilyInet)
	binary.BigEndian.PutUint16(socketAddress[2:4], port)
	copy(socketAddress[4:8], ip.To4())
	return socketAddress
}

func TestExtractInetConnect(t *testing.T) {
	eventReader := newEnrichedEventReader(t, 1, processContext{}, pb.MessageType_MESSAGE_SYSCALL_CONNECT, &pb.Connect{
		Fd:      3,
		Address: inetSocketAddress(net.ParseIP("10.96.0.1"), 443),
		Exit:    &pb.Exit{Result: -115, Errorno: 115},
	})
	assertExtractedValues(t, &Plugin{}, eventReader, map[string]any{
		"fd.num":       uint64(3),
		"fd.name":      "10.96.0.1:443",
		"fd.type":      "ipv4",
		"fd.typechar":  "4",
		"fd.sip":       net.ParseIP("10.96.0.1").To4(),
		"fd.rip":       net.ParseIP("10.96.0.1").To4(),
		"fd.sport":     uint64(443),
		"fd.rport":     uint64(443),
		"evt.res":      "EINPROGRESS",
		"fd.directory": nil,
	})
}

func TestExtractInet6AndUnixConnect(t *testing.T) {
	inet6Address := make([]byte, 28)
	binary.LittleEndian.PutUint16(inet6Address[0:2], linuxAddressFamilyInet6)
	binary.BigEndian.PutUint16(inet6Address[2:4], 22)
	copy(inet6Address[8:24], net.ParseIP("2001:db8::1"))
	inet6Reader := newEnrichedEventReader(t, 1, processContext{}, pb.MessageType_MESSAGE_SYSCALL_CONNECT, &pb.Connect{Address: inet6Address})
	assertExtractedValues(t, &Plugin{}, inet6Reader, map[string]any{
		"fd.name":     "[2001:db8::1]:22",
		"fd.typechar": "6",
		"fd.rport":    uint64(22),
	})

	unixAddress := append([]byte{linuxAddressFamilyUnix, 0}, []byte("/var/run/nscd/socket\x00")...)
	unixReader := newEnrichedEventReader(t, 2, processContext{}, pb.MessageType_MESSAGE_SYSCALL_CONNECT, &pb.Connect{Address: unixAddress})
	assertExtractedValues(t, &Plugin{}, unixReader, map[string]any{
		"fd.name":  "/var/run/nscd/socket",
		"fd.type":  "unix",
		"fd.sip":   nil,
		"fd.rport": nil,
	})

	abstractAddress := append([]byte{linuxAddressFamilyUnix, 0, 0}, []byte("containerd-shim")...)
	abstractReader := newEnrichedEventReader(t, 3, processContext{}, pb.MessageType_MESSAGE_SYSCALL_CONNECT, &pb.Connect{Address: abstractAddress})
	assertExtractedValues(t, &Plugin{}, abstractReader, map[string]any{"fd.name": "@containerd-shim"})
}

func TestExtractPtraceRequestAndSocketDomain(t *testing.T) {
	ptraceReader := newEnrichedEventReader(t, 1, processContext{}, pb.MessageType_MESSAGE_SYSCALL_PTRACE, &pb.Ptrace{Request: 16})
	assertExtractedValues(t, &Plugin{}, ptraceReader, map[string]any{"evt.arg.request": "PTRACE_ATTACH", "evt.arg.flags": nil})

	socketReader := newEnrichedEventReader(t, 2, processContext{}, pb.MessageType_MESSAGE_SYSCALL_SOCKET, &pb.Socket{
		Domain: linuxAddressFamilyPacket,
		Exit:   &pb.Exit{Result: 5},
	})
	assertExtractedValues(t, &Plugin{}, socketReader, map[string]any{
		"evt.arg.domain":  "AF_PACKET",
		"fd.num":          uint64(5),
		"evt.arg.request": nil,
	})
}

func TestExtractProcessAndAncestorFields(t *testing.T) {
	context := processContext{
		Process: &processInfo{
			PID: 30, ParentPID: 20, Name: "cat", ExeArgument: "cat", ExePath: "/usr/bin/cat",
			Args: []string{"/etc/shadow"}, TerminalDevice: 34816, IsExeUpperLayer: true, StdinType: "ipv4",
		},
		Ancestors: []processInfo{
			{PID: 20, ParentPID: 10, Name: "bash", ExeArgument: "-bash", ExePath: "/bin/bash", Args: []string{"-i"}},
			{PID: 10, ParentPID: 1, Name: "nginx", ExePath: "/usr/sbin/nginx"},
			{PID: 1, Name: "tini", ExePath: "/sbin/tini"},
		},
	}
	eventReader := newEnrichedEventReader(t, 1, context, pb.MessageType_MESSAGE_SYSCALL_OPEN, &pb.Open{
		ContextData: &pb.ContextData{
			ThreadId: 31, ThreadGroupId: 30, ProcessName: "cat",
			Credentials: &pb.Credentials{EffectiveUid: 1000, EffectiveGid: 100},
		},
	})
	plugin := &Plugin{}
	assertExtractedValues(t, plugin, eventReader, map[string]any{
		"proc.pid":                uint64(30),
		"thread.tid":              uint64(31),
		"proc.name":               "cat",
		"proc.exe":                "cat",
		"proc.exepath":            "/usr/bin/cat",
		"proc.args":               "/etc/shadow",
		"proc.cmdline":            "cat /etc/shadow",
		"proc.tty":                uint64(34816),
		"proc.is_exe_upper_layer": true,
		"proc.is_exe_from_memfd":  false,
		"proc.stdin.type":         "ipv4",
		"proc.stdout.type":        nil,
		"proc.ppid":               uint64(20),
		"proc.pname":              "bash",
		"proc.pexe":               "-bash",
		"proc.pexepath":           "/bin/bash",
		"proc.pcmdline":           "bash -i",
		"user.uid":                uint64(1000),
		"group.gid":               uint64(100),
		"gvisor.anames":           []string{"bash", "nginx", "tini"},
	})

	expectedAncestorNames := map[uint64]any{0: "cat", 1: "bash", 2: "nginx", 3: "tini", 4: nil}
	for ancestorIndex, expectedName := range expectedAncestorNames {
		if ancestorName := extractIndexedField(t, plugin, eventReader, "proc.aname", ancestorIndex); ancestorName != expectedName {
			t.Errorf("proc.aname[%d] = %v, want %v", ancestorIndex, ancestorName, expectedName)
		}
	}
	if ancestorPath := extractIndexedField(t, plugin, eventReader, "proc.aexepath", 2); ancestorPath != "/usr/sbin/nginx" {
		t.Errorf("proc.aexepath[2] = %v", ancestorPath)
	}
	if ancestorPID := extractIndexedField(t, plugin, eventReader, "proc.apid", 3); ancestorPID != uint64(1) {
		t.Errorf("proc.apid[3] = %v", ancestorPID)
	}
}

func TestExtractWithoutProcessContextFallsBackToContextFields(t *testing.T) {
	eventReader := newEnrichedEventReader(t, 1, processContext{}, pb.MessageType_MESSAGE_SYSCALL_OPEN, &pb.Open{
		ContextData: &pb.ContextData{ProcessName: "sh"},
	})
	assertExtractedValues(t, &Plugin{}, eventReader, map[string]any{
		"proc.name":    "sh",
		"proc.cmdline": nil,
		"proc.pname":   nil,
		"user.uid":     nil,
	})
}

func TestFormatLinuxOpenFlagsDistinguishesSyncFromDataSync(t *testing.T) {
	if flags := formatLinuxOpenFlags(linuxOpenReadWrite | linuxOpenSync); flags != "O_RDWR|O_SYNC" {
		t.Errorf("flags = %q, want O_RDWR|O_SYNC", flags)
	}
	if flags := formatLinuxOpenFlags(linuxOpenReadOnly | linuxOpenDataSync); flags != "O_RDONLY|O_DSYNC" {
		t.Errorf("flags = %q, want O_RDONLY|O_DSYNC", flags)
	}
}
