//go:build !amd64 && !arm64

package gvisor

// gVisor は amd64 / arm64 のみをサポートするため、それ以外では syscall 名を解決しない。
// evt.type はメッセージ種別から決まる名前にフォールバックする。
var syscallNamesByNumber = map[uint64]string{}
