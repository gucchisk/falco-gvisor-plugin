package gvisor

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// Falco に送るイベントデータの形式:
//
//	+-------+----------------------+------------------------+--------------------------------+
//	| magic | processContextLength | processContext (JSON)  | gVisor packet (header+protobuf) |
//	| 4byte | uint32 little-endian |                        |                                |
//	+-------+----------------------+------------------------+--------------------------------+
//
// gVisor のパケットは受信したものをそのまま残し、受信時点のプロセス表から作った
// プロセス情報を前に付ける。フィールド抽出時にプロセス表を参照しないため、
// キャプチャファイルを再生しても同じ結果になる。
var enrichedEventMagic = []byte("GVP1")

const (
	enrichedEventHeaderSize = 8
	// maxProcessContextBytes は 1 イベントに埋め込むプロセス情報 (JSON) の最大サイズ。
	maxProcessContextBytes = 32 * 1024
)

// enrichedEvent はフィールド抽出に使う、デコード済みのイベント。
type enrichedEvent struct {
	GVisorEvent    *gVisorEvent
	ProcessContext processContext
}

// encodeEnrichedEvent はプロセス情報と gVisor のパケットを 1 つのイベントデータにまとめる。
func encodeEnrichedEvent(context processContext, gVisorPacket []byte) ([]byte, error) {
	contextJSON, err := marshalProcessContextWithinLimit(context)
	if err != nil {
		return nil, err
	}
	eventData := make([]byte, enrichedEventHeaderSize, enrichedEventHeaderSize+len(contextJSON)+len(gVisorPacket))
	copy(eventData, enrichedEventMagic)
	binary.LittleEndian.PutUint32(eventData[4:8], uint32(len(contextJSON)))
	eventData = append(eventData, contextJSON...)
	return append(eventData, gVisorPacket...), nil
}

// marshalProcessContextWithinLimit は JSON が maxProcessContextBytes に収まるよう、
// 大きい場合は引数、祖先の順に情報を減らす。
func marshalProcessContextWithinLimit(context processContext) ([]byte, error) {
	contextJSON, err := json.Marshal(context)
	if err != nil || len(contextJSON) <= maxProcessContextBytes {
		return contextJSON, err
	}
	if context.Process != nil {
		processWithoutArgs := *context.Process
		processWithoutArgs.Args = nil
		context.Process = &processWithoutArgs
	}
	ancestorsWithoutArgs := make([]processInfo, len(context.Ancestors))
	for ancestorIndex, ancestor := range context.Ancestors {
		ancestor.Args = nil
		ancestorsWithoutArgs[ancestorIndex] = ancestor
	}
	context.Ancestors = ancestorsWithoutArgs
	if contextJSON, err = json.Marshal(context); err != nil || len(contextJSON) <= maxProcessContextBytes {
		return contextJSON, err
	}
	context.Ancestors = nil
	return json.Marshal(context)
}

// decodeEnrichedEvent は encodeEnrichedEvent で作ったイベントデータをデコードする。
func decodeEnrichedEvent(eventData []byte) (*enrichedEvent, error) {
	if len(eventData) < enrichedEventHeaderSize || !bytes.Equal(eventData[:4], enrichedEventMagic) {
		return nil, fmt.Errorf("not a gvisor plugin event (missing %q header)", enrichedEventMagic)
	}
	contextLength := int(binary.LittleEndian.Uint32(eventData[4:8]))
	if contextLength > len(eventData)-enrichedEventHeaderSize {
		return nil, fmt.Errorf("invalid process context length: %d (event %d bytes)", contextLength, len(eventData))
	}
	contextJSON := eventData[enrichedEventHeaderSize : enrichedEventHeaderSize+contextLength]

	decodedEvent := &enrichedEvent{}
	if err := json.Unmarshal(contextJSON, &decodedEvent.ProcessContext); err != nil {
		return nil, fmt.Errorf("unmarshalling process context: %w", err)
	}
	gVisorEvent, err := decodeGVisorEvent(eventData[enrichedEventHeaderSize+contextLength:])
	if err != nil {
		return nil, err
	}
	decodedEvent.GVisorEvent = gVisorEvent
	return decodedEvent, nil
}
