package gvisor

import (
	"encoding/binary"
	"net"
	"path"
	"strconv"
	"strings"

	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

// linuxAtCurrentWorkingDirectory は openat(2) などの AT_FDCWD。
const linuxAtCurrentWorkingDirectory = -100

// syscallResult は syscall の exit point に含まれる戻り値。
type syscallResult struct {
	ReturnValue int64
	Errno       int64
}

func (result syscallResult) Failed() bool { return result.Errno != 0 }

// SyscallResult は exit point のイベントなら戻り値を返す。enter point や sentry 系のイベントでは false。
func (event *gVisorEvent) SyscallResult() (syscallResult, bool) {
	messageWithExit, hasExitField := event.Message.(interface{ GetExit() *pb.Exit })
	if !hasExitField || messageWithExit.GetExit() == nil {
		return syscallResult{}, false
	}
	exit := messageWithExit.GetExit()
	return syscallResult{ReturnValue: exit.GetResult(), Errno: exit.GetErrorno()}, true
}

// fileDescriptorInfo はイベントが対象とするファイルディスクリプタの情報 (Falco の fd.* に相当)。
type fileDescriptorInfo struct {
	Number    int64
	HasNumber bool
	// Name は Falco の fd.name に相当する。ファイルなら絶対パス、inet ソケットなら "IP:ポート"。
	Name string
	// RawName は Falco の fd.nameraw に相当する (syscall に渡されたままのパス)。
	RawName string
	// Type は Falco の fd.type に相当する ("file", "directory", "ipv4", "ipv6", "unix" など)。
	Type     string
	RemoteIP net.IP
	// RemotePort は inet ソケットの接続先ポート。0 なら値なし。
	RemotePort uint16
}

// TypeChar は Falco の fd.typechar に相当する 1 文字の種類を返す。
func (fileDescriptor fileDescriptorInfo) TypeChar() string {
	switch fileDescriptor.Type {
	case "file":
		return "f"
	case "directory":
		return "d"
	case "ipv4":
		return "4"
	case "ipv6":
		return "6"
	case "unix":
		return "u"
	case "pipe":
		return "p"
	case "netlink":
		return "n"
	default:
		return ""
	}
}

// IsFile は fd.name をファイルのパスとして扱えるか (fd.directory / fd.filename を返せるか) を返す。
func (fileDescriptor fileDescriptorInfo) IsFile() bool {
	return fileDescriptor.Type == "file" || fileDescriptor.Type == "directory"
}

// FileDescriptor はイベントが対象とするファイルディスクリプタを返す。
// 相対パスの解決には、イベントを発生させたプロセスのカレントディレクトリを使う。
func (event *gVisorEvent) FileDescriptor(currentWorkingDirectory string) (fileDescriptorInfo, bool) {
	result, hasResult := event.SyscallResult()
	succeeded := hasResult && !result.Failed()

	switch message := event.Message.(type) {
	case *pb.Open:
		fileDescriptor := fileDescriptorInfo{
			RawName: message.GetPathname(),
			Name:    resolveOpenedPath(message, currentWorkingDirectory),
			Type:    "file",
		}
		if message.GetFlags()&linuxOpenDirectory != 0 {
			fileDescriptor.Type = "directory"
		}
		if succeeded {
			// open が成功した場合だけ、Falco と同じく戻り値の fd 番号を fd.num とする。
			fileDescriptor.Number, fileDescriptor.HasNumber = result.ReturnValue, true
		}
		return fileDescriptor, true
	case *pb.Connect:
		fileDescriptor := describeSocketAddress(message.GetAddress())
		fileDescriptor.Number, fileDescriptor.HasNumber = message.GetFd(), true
		return fileDescriptor, true
	case *pb.Socket:
		fileDescriptor := fileDescriptorInfo{Type: socketFamilyToFileDescriptorType(int64(message.GetDomain()))}
		if succeeded {
			fileDescriptor.Number, fileDescriptor.HasNumber = result.ReturnValue, true
		}
		return fileDescriptor, true
	case *pb.Dup:
		// fd_path の optional field が有効な場合だけ複製元のパスが入る。
		return fileDescriptorInfo{
			Number:    int64(message.GetOldFd()),
			HasNumber: true,
			Name:      message.GetFdPath(),
			RawName:   message.GetFdPath(),
		}, true
	default:
		return fileDescriptorInfo{}, false
	}
}

// resolveOpenedPath は open 系 syscall で開いたファイルの絶対パスを求める。
// 相対パスは dirfd のパス (fd_path の optional field) かカレントディレクトリ (cwd の context field) を基準にする。
func resolveOpenedPath(open *pb.Open, currentWorkingDirectory string) string {
	pathname := open.GetPathname()
	if pathname == "" {
		return ""
	}
	if path.IsAbs(pathname) {
		return path.Clean(pathname)
	}
	baseDirectory := currentWorkingDirectory
	if open.GetFd() != linuxAtCurrentWorkingDirectory {
		baseDirectory = open.GetFdPath()
	}
	if !path.IsAbs(baseDirectory) {
		// 基準ディレクトリが分からない場合は、渡されたままのパスを返す。
		return pathname
	}
	return path.Join(baseDirectory, pathname)
}

// describeSocketAddress は connect(2) などに渡された struct sockaddr を解釈する。
func describeSocketAddress(socketAddress []byte) fileDescriptorInfo {
	if len(socketAddress) < 2 {
		return fileDescriptorInfo{}
	}
	// sa_family はホストのバイトオーダー (gVisor が動く amd64 / arm64 はリトルエンディアン)、
	// ポートはネットワークバイトオーダー。
	family := int64(binary.LittleEndian.Uint16(socketAddress[0:2]))
	fileDescriptor := fileDescriptorInfo{Type: socketFamilyToFileDescriptorType(family)}
	switch family {
	case linuxAddressFamilyInet:
		if len(socketAddress) >= 8 {
			fileDescriptor.RemotePort = binary.BigEndian.Uint16(socketAddress[2:4])
			fileDescriptor.RemoteIP = net.IP(append([]byte(nil), socketAddress[4:8]...))
		}
	case linuxAddressFamilyInet6:
		if len(socketAddress) >= 24 {
			fileDescriptor.RemotePort = binary.BigEndian.Uint16(socketAddress[2:4])
			fileDescriptor.RemoteIP = net.IP(append([]byte(nil), socketAddress[8:24]...))
		}
	case linuxAddressFamilyUnix:
		fileDescriptor.Name = unixSocketPath(socketAddress[2:])
		fileDescriptor.RawName = fileDescriptor.Name
	}
	if fileDescriptor.RemoteIP != nil {
		fileDescriptor.Name = net.JoinHostPort(fileDescriptor.RemoteIP.String(), strconv.Itoa(int(fileDescriptor.RemotePort)))
		fileDescriptor.RawName = fileDescriptor.Name
	}
	return fileDescriptor
}

// unixSocketPath は sun_path を文字列にする。先頭が NUL の abstract socket は "@名前" で表す。
func unixSocketPath(socketPath []byte) string {
	if len(socketPath) > 0 && socketPath[0] == 0 {
		return "@" + strings.TrimRight(string(socketPath[1:]), "\x00")
	}
	if nullIndex := strings.IndexByte(string(socketPath), 0); nullIndex >= 0 {
		socketPath = socketPath[:nullIndex]
	}
	return string(socketPath)
}

// ArgumentFlags は Falco の evt.arg.flags に相当する文字列を返す (open 系のみ)。
func (event *gVisorEvent) ArgumentFlags() (string, bool) {
	if open, isOpen := event.Message.(*pb.Open); isOpen {
		return formatLinuxOpenFlags(open.GetFlags()), true
	}
	return "", false
}

// OpenFlags は open 系イベントのフラグを返す。
func (event *gVisorEvent) OpenFlags() (uint32, bool) {
	if open, isOpen := event.Message.(*pb.Open); isOpen {
		return open.GetFlags(), true
	}
	return 0, false
}

// ArgumentRequest は Falco の evt.arg.request に相当する文字列を返す (ptrace のみ)。
func (event *gVisorEvent) ArgumentRequest() (string, bool) {
	if ptrace, isPtrace := event.Message.(*pb.Ptrace); isPtrace {
		return linuxPtraceRequestName(ptrace.GetRequest()), true
	}
	return "", false
}

// ArgumentDomain は Falco の evt.arg.domain に相当する文字列を返す (socket のみ)。
func (event *gVisorEvent) ArgumentDomain() (string, bool) {
	if socket, isSocket := event.Message.(*pb.Socket); isSocket {
		return linuxAddressFamilyName(int64(socket.GetDomain())), true
	}
	return "", false
}
