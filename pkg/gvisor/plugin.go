// Package gvisor は gVisor の Runtime Monitoring (remote sink) から送られる
// syscall イベントを Falco に取り込むプラグインを実装する。
package gvisor

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

const (
	PluginID          uint32 = 999 // Falco のプラグインレジストリで開発・テスト用に予約されている ID
	PluginName               = "gvisor"
	PluginDescription        = "Receives syscall events from gVisor runtime monitoring and sends them to Falco"
	PluginContact            = "github.com/gucchi/falco-gvisor-plugin"
	PluginVersion            = "0.2.0"
	PluginEventSource        = "gvisor"

	defaultSocketPath   = "/run/falco/gvisor.sock"
	defaultMaxEventSize = 64 * 1024
	eventChannelSize    = 4096
)

// PluginConfig は falco.yaml の init_config で指定するプラグイン設定。
type PluginConfig struct {
	// SocketPath は gVisor の remote sink が接続してくる Unix ソケットのパス。
	// runsc の trace session 設定の sinks[].config.endpoint と一致させる必要がある。
	SocketPath string `json:"socketPath"`
	// MaxEventSize は 1 イベントの最大バイト数。これより大きいメッセージは破棄される。
	MaxEventSize uint32 `json:"maxEventSize"`
}

// Plugin は gVisor のイベントソース兼フィールド抽出プラグイン。
type Plugin struct {
	plugins.BasePlugin
	config PluginConfig

	// Falco は同一イベントに対して複数フィールドを順に抽出するため、
	// 直前にデコードしたイベントを保持して再デコードを避ける。
	cachedEventNumber uint64
	cachedEvent       *enrichedEvent
}

func (p *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          PluginID,
		Name:        PluginName,
		Description: PluginDescription,
		Contact:     PluginContact,
		Version:     PluginVersion,
		EventSource: PluginEventSource,
	}
}

func (p *Plugin) InitSchema() *sdk.SchemaInfo {
	return &sdk.SchemaInfo{
		Schema: `{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "type": "object",
  "properties": {
    "socketPath": {
      "type": "string",
      "description": "Unix socket path that gVisor remote sink connects to (default: ` + defaultSocketPath + `)"
    },
    "maxEventSize": {
      "type": "integer",
      "minimum": 1024,
      "description": "Maximum size in bytes of a single gVisor message (default: 65536)"
    }
  },
  "additionalProperties": false
}`,
	}
}

func (p *Plugin) Init(config string) error {
	p.config = PluginConfig{
		SocketPath:   defaultSocketPath,
		MaxEventSize: defaultMaxEventSize,
	}
	if config != "" {
		if err := json.Unmarshal([]byte(config), &p.config); err != nil {
			return fmt.Errorf("parsing init config: %w", err)
		}
	}
	return nil
}

// Open は gVisor からの接続を待ち受けるソケットを開く。
// open_params が指定された場合はソケットパスとして init_config の値より優先する。
func (p *Plugin) Open(params string) (source.Instance, error) {
	socketPath := p.config.SocketPath
	if params != "" {
		socketPath = params
	}

	events := make(chan source.PushEvent, eventChannelSize)
	server := newGVisorEventServer(socketPath, p.config.MaxEventSize, events)
	if err := server.Start(); err != nil {
		return nil, err
	}
	return source.NewPushInstance(
		events,
		// gVisor のメッセージにプロセス情報を付け足すため、その分だけ大きくする。
		source.WithInstanceEventSize(p.config.MaxEventSize+enrichedEventHeaderSize+maxProcessContextBytes),
		source.WithInstanceClose(server.Stop),
	)
}

func (p *Plugin) Fields() []sdk.FieldEntry {
	fieldEntries := make([]sdk.FieldEntry, 0, len(fieldDefinitions))
	for _, definition := range fieldDefinitions {
		fieldEntries = append(fieldEntries, definition.entry)
	}
	return fieldEntries
}

func (p *Plugin) Extract(request sdk.ExtractRequest, eventReader sdk.EventReader) error {
	event, err := p.decodeEventWithCache(eventReader)
	if err != nil {
		return err
	}
	extract, found := fieldExtractorsByName[request.Field()]
	if !found {
		return fmt.Errorf("unsupported field: %s", request.Field())
	}
	extract(event, request)
	return nil
}

// String は falco の出力 (%evt.plugininfo) などで使われるイベントの文字列表現を返す。
func (p *Plugin) String(eventReader sdk.EventReader) (string, error) {
	event, err := p.decodeEventWithCache(eventReader)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("evt.type=%s proc.name=%s container_id=%s",
		event.GVisorEvent.EventType(), event.ProcessName(), event.GVisorEvent.ContextData.GetContainerId()), nil
}

func (p *Plugin) decodeEventWithCache(eventReader sdk.EventReader) (*enrichedEvent, error) {
	eventNumber := eventReader.EventNum()
	if p.cachedEvent != nil && p.cachedEventNumber == eventNumber {
		return p.cachedEvent, nil
	}
	eventData, err := io.ReadAll(eventReader.Reader())
	if err != nil {
		return nil, err
	}
	event, err := decodeEnrichedEvent(eventData)
	if err != nil {
		return nil, err
	}
	p.cachedEventNumber = eventNumber
	p.cachedEvent = event
	return event, nil
}
