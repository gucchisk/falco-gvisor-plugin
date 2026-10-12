//go:build !amd64

package gvisor

// asm-generic (arm64 など) の open(2) フラグのうち、アーキテクチャによって値が異なるもの。
const (
	linuxOpenDirectory = 0x4000
	linuxOpenNoFollow  = 0x8000
	linuxOpenDirect    = 0x10000
	linuxOpenLargeFile = 0x20000
)
