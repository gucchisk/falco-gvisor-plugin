package gvisor

import (
	"fmt"
	"strings"
)

// gVisor はサンドボックス内の Linux の値をそのまま送ってくるため、プラグインを
// ビルドした OS の定数 (golang.org/x/sys/unix など) ではなく、Linux の値で解釈する。

// linuxErrnoNames は Linux の errno 番号と名前の対応 (asm-generic。amd64 / arm64 共通)。
// Falco の evt.res と同じく、失敗した syscall の結果を "ENOENT" のような名前で表すために使う。
var linuxErrnoNames = map[int64]string{
	1: "EPERM", 2: "ENOENT", 3: "ESRCH", 4: "EINTR", 5: "EIO", 6: "ENXIO", 7: "E2BIG", 8: "ENOEXEC",
	9: "EBADF", 10: "ECHILD", 11: "EAGAIN", 12: "ENOMEM", 13: "EACCES", 14: "EFAULT", 15: "ENOTBLK",
	16: "EBUSY", 17: "EEXIST", 18: "EXDEV", 19: "ENODEV", 20: "ENOTDIR", 21: "EISDIR", 22: "EINVAL",
	23: "ENFILE", 24: "EMFILE", 25: "ENOTTY", 26: "ETXTBSY", 27: "EFBIG", 28: "ENOSPC", 29: "ESPIPE",
	30: "EROFS", 31: "EMLINK", 32: "EPIPE", 33: "EDOM", 34: "ERANGE", 35: "EDEADLK", 36: "ENAMETOOLONG",
	37: "ENOLCK", 38: "ENOSYS", 39: "ENOTEMPTY", 40: "ELOOP", 42: "ENOMSG", 43: "EIDRM", 61: "ENODATA",
	62: "ETIME", 71: "EPROTO", 74: "EBADMSG", 75: "EOVERFLOW", 84: "EILSEQ", 88: "ENOTSOCK",
	89: "EDESTADDRREQ", 90: "EMSGSIZE", 91: "EPROTOTYPE", 92: "ENOPROTOOPT", 93: "EPROTONOSUPPORT",
	94: "ESOCKTNOSUPPORT", 95: "EOPNOTSUPP", 96: "EPFNOSUPPORT", 97: "EAFNOSUPPORT", 98: "EADDRINUSE",
	99: "EADDRNOTAVAIL", 100: "ENETDOWN", 101: "ENETUNREACH", 102: "ENETRESET", 103: "ECONNABORTED",
	104: "ECONNRESET", 105: "ENOBUFS", 106: "EISCONN", 107: "ENOTCONN", 108: "ESHUTDOWN",
	109: "ETOOMANYREFS", 110: "ETIMEDOUT", 111: "ECONNREFUSED", 112: "EHOSTDOWN", 113: "EHOSTUNREACH",
	114: "EALREADY", 115: "EINPROGRESS", 116: "ESTALE", 122: "EDQUOT", 125: "ECANCELED",
	130: "EOWNERDEAD", 131: "ENOTRECOVERABLE",
}

// linuxErrnoName は errno 番号を名前に変換する。表にない番号は "E<番号>" とする。
func linuxErrnoName(errno int64) string {
	if errnoName, found := linuxErrnoNames[errno]; found {
		return errnoName
	}
	return fmt.Sprintf("E%d", errno)
}

// Linux の open(2) フラグのうちアーキテクチャに依存しないもの。
// O_DIRECT / O_LARGEFILE / O_DIRECTORY / O_NOFOLLOW は openflags_*.go で定義する。
const (
	linuxOpenAccessModeMask = 0x3
	linuxOpenReadOnly       = 0x0
	linuxOpenWriteOnly      = 0x1
	linuxOpenReadWrite      = 0x2
	linuxOpenCreate         = 0x40
	linuxOpenExclusive      = 0x80
	linuxOpenNoCTTY         = 0x100
	linuxOpenTruncate       = 0x200
	linuxOpenAppend         = 0x400
	linuxOpenNonBlocking    = 0x800
	linuxOpenDataSync       = 0x1000
	linuxOpenAsync          = 0x2000
	linuxOpenNoAccessTime   = 0x40000
	linuxOpenCloseOnExec    = 0x80000
	linuxOpenSync           = 0x101000
	linuxOpenPath           = 0x200000
	linuxOpenTemporaryFile  = 0x400000 // O_TMPFILE は O_DIRECTORY と組み合わせて指定される
)

type linuxFlagName struct {
	value uint32
	name  string
}

// linuxOpenFlagNames は Falco と同じ "O_WRONLY|O_CREAT|O_TRUNC" 形式の文字列を作るための表。
// O_SYNC は O_DSYNC を含むため、O_SYNC を先に判定する。
var linuxOpenFlagNames = []linuxFlagName{
	{linuxOpenCreate, "O_CREAT"},
	{linuxOpenExclusive, "O_EXCL"},
	{linuxOpenNoCTTY, "O_NOCTTY"},
	{linuxOpenTruncate, "O_TRUNC"},
	{linuxOpenAppend, "O_APPEND"},
	{linuxOpenNonBlocking, "O_NONBLOCK"},
	{linuxOpenSync, "O_SYNC"},
	{linuxOpenDataSync, "O_DSYNC"},
	{linuxOpenAsync, "O_ASYNC"},
	{linuxOpenDirect, "O_DIRECT"},
	{linuxOpenLargeFile, "O_LARGEFILE"},
	{linuxOpenDirectory, "O_DIRECTORY"},
	{linuxOpenNoFollow, "O_NOFOLLOW"},
	{linuxOpenNoAccessTime, "O_NOATIME"},
	{linuxOpenCloseOnExec, "O_CLOEXEC"},
	{linuxOpenPath, "O_PATH"},
	{linuxOpenTemporaryFile, "O_TMPFILE"},
}

// formatLinuxOpenFlags は open(2) のフラグを Falco の evt.arg.flags と同じ形式の文字列にする。
func formatLinuxOpenFlags(flags uint32) string {
	var flagNames []string
	switch flags & linuxOpenAccessModeMask {
	case linuxOpenReadOnly:
		flagNames = append(flagNames, "O_RDONLY")
	case linuxOpenWriteOnly:
		flagNames = append(flagNames, "O_WRONLY")
	case linuxOpenReadWrite:
		flagNames = append(flagNames, "O_RDWR")
	}
	remainingFlags := flags &^ linuxOpenAccessModeMask
	for _, flagName := range linuxOpenFlagNames {
		if remainingFlags&flagName.value == flagName.value {
			flagNames = append(flagNames, flagName.name)
			remainingFlags &^= flagName.value
		}
	}
	return strings.Join(flagNames, "|")
}

// isLinuxOpenForRead / isLinuxOpenForWrite は Falco の evt.is_open_read / evt.is_open_write と同じ判定。
func isLinuxOpenForRead(flags uint32) bool {
	accessMode := flags & linuxOpenAccessModeMask
	return accessMode == linuxOpenReadOnly || accessMode == linuxOpenReadWrite
}

func isLinuxOpenForWrite(flags uint32) bool {
	accessMode := flags & linuxOpenAccessModeMask
	return accessMode == linuxOpenWriteOnly || accessMode == linuxOpenReadWrite
}

// linuxPtraceRequestNames は ptrace(2) の request 番号と名前の対応。
var linuxPtraceRequestNames = map[int64]string{
	0: "PTRACE_TRACEME", 1: "PTRACE_PEEKTEXT", 2: "PTRACE_PEEKDATA", 3: "PTRACE_PEEKUSR",
	4: "PTRACE_POKETEXT", 5: "PTRACE_POKEDATA", 6: "PTRACE_POKEUSR", 7: "PTRACE_CONT",
	8: "PTRACE_KILL", 9: "PTRACE_SINGLESTEP", 12: "PTRACE_GETREGS", 13: "PTRACE_SETREGS",
	14: "PTRACE_GETFPREGS", 15: "PTRACE_SETFPREGS", 16: "PTRACE_ATTACH", 17: "PTRACE_DETACH",
	18: "PTRACE_GETFPXREGS", 19: "PTRACE_SETFPXREGS", 24: "PTRACE_SYSCALL",
	0x4200: "PTRACE_SETOPTIONS", 0x4201: "PTRACE_GETEVENTMSG", 0x4202: "PTRACE_GETSIGINFO",
	0x4203: "PTRACE_SETSIGINFO", 0x4204: "PTRACE_GETREGSET", 0x4205: "PTRACE_SETREGSET",
	0x4206: "PTRACE_SEIZE", 0x4207: "PTRACE_INTERRUPT", 0x4208: "PTRACE_LISTEN",
}

func linuxPtraceRequestName(request int64) string {
	if requestName, found := linuxPtraceRequestNames[request]; found {
		return requestName
	}
	return fmt.Sprintf("PTRACE_UNKNOWN(%d)", request)
}

// Linux のソケットアドレスファミリ。
const (
	linuxAddressFamilyUnix    = 1
	linuxAddressFamilyInet    = 2
	linuxAddressFamilyInet6   = 10
	linuxAddressFamilyNetlink = 16
	linuxAddressFamilyPacket  = 17
)

var linuxAddressFamilyNames = map[int64]string{
	0: "AF_UNSPEC", linuxAddressFamilyUnix: "AF_UNIX", linuxAddressFamilyInet: "AF_INET",
	linuxAddressFamilyInet6: "AF_INET6", linuxAddressFamilyNetlink: "AF_NETLINK",
	linuxAddressFamilyPacket: "AF_PACKET", 38: "AF_ALG", 40: "AF_VSOCK",
}

func linuxAddressFamilyName(family int64) string {
	if familyName, found := linuxAddressFamilyNames[family]; found {
		return familyName
	}
	return fmt.Sprintf("AF_UNKNOWN(%d)", family)
}

// Linux の st_mode のファイル種別。
const (
	linuxFileTypeMask       = 0o170000
	linuxFileTypeSocket     = 0o140000
	linuxFileTypeDirectory  = 0o040000
	linuxFileTypeCharDevice = 0o020000
	linuxFileTypeNamedPipe  = 0o010000
)
