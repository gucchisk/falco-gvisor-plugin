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
	PluginVersion            = "0.1.0"
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
	cachedEvent       *gVisorEvent
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
		source.WithInstanceEventSize(p.config.MaxEventSize),
		source.WithInstanceClose(server.Stop),
	)
}

func (p *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "proc.name", Display: "Process Name", Desc: "The name (excluding the path) of the executable generating the event. Requires the 'process_name' context field in the gVisor trace session."},
		{Type: "string", Name: "evt.type", Display: "Event Type", Desc: "The name of the event (e.g. 'openat', 'execve'). For non-syscall gVisor points, the point name (e.g. 'sentry_clone', 'container_start')."},
		{Type: "uint64", Name: "gvisor.sysno", Display: "Syscall Number", Desc: "The raw syscall number reported by gVisor."},
		{Type: "string", Name: "gvisor.container_id", Display: "Container ID", Desc: "The container ID reported by gVisor. Requires the 'container_id' context field."},
		{Type: "uint64", Name: "gvisor.pid", Display: "Process ID", Desc: "The thread group ID (PID) inside the sandbox. Requires the 'group_id' context field."},
		{Type: "uint64", Name: "gvisor.tid", Display: "Thread ID", Desc: "The thread ID inside the sandbox. Requires the 'thread_id' context field."},
	}
}

func (p *Plugin) Extract(request sdk.ExtractRequest, eventReader sdk.EventReader) error {
	event, err := p.decodeEventWithCache(eventReader)
	if err != nil {
		return err
	}

	switch request.Field() {
	case "proc.name":
		request.SetValue(event.ProcessName())
	case "evt.type":
		request.SetValue(event.EventType())
	case "gvisor.sysno":
		if !event.HasSyscall {
			return nil // syscall 以外のイベントでは値なし
		}
		request.SetValue(event.SyscallNumber)
	case "gvisor.container_id":
		request.SetValue(event.ContextData.GetContainerId())
	case "gvisor.pid":
		request.SetValue(uint64(event.ContextData.GetThreadGroupId()))
	case "gvisor.tid":
		request.SetValue(uint64(event.ContextData.GetThreadId()))
	default:
		return fmt.Errorf("unsupported field: %s", request.Field())
	}
	return nil
}

// String は falco の出力 (%evt.plugininfo) などで使われるイベントの文字列表現を返す。
func (p *Plugin) String(eventReader sdk.EventReader) (string, error) {
	event, err := p.decodeEventWithCache(eventReader)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("evt.type=%s proc.name=%s container_id=%s",
		event.EventType(), event.ProcessName(), event.ContextData.GetContainerId()), nil
}

func (p *Plugin) decodeEventWithCache(eventReader sdk.EventReader) (*gVisorEvent, error) {
	eventNumber := eventReader.EventNum()
	if p.cachedEvent != nil && p.cachedEventNumber == eventNumber {
		return p.cachedEvent, nil
	}
	packet, err := io.ReadAll(eventReader.Reader())
	if err != nil {
		return nil, err
	}
	event, err := decodeGVisorEvent(packet)
	if err != nil {
		return nil, err
	}
	p.cachedEventNumber = eventNumber
	p.cachedEvent = event
	return event, nil
}
