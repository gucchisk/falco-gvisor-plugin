//go:build amd64

package gvisor

// x86_64 の open(2) フラグのうち、アーキテクチャによって値が異なるもの。
const (
	linuxOpenDirect    = 0x4000
	linuxOpenLargeFile = 0x8000
	linuxOpenDirectory = 0x10000
	linuxOpenNoFollow  = 0x20000
)
