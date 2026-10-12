// main パッケージは Falco がロードする共有ライブラリ (libgvisor.so) のエントリポイント。
package main

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"

	"github.com/gucchi/falco-gvisor-plugin/pkg/gvisor"
)

func init() {
	plugins.SetFactory(func() plugins.Plugin {
		gvisorPlugin := &gvisor.Plugin{}
		source.Register(gvisorPlugin)
		extractor.Register(gvisorPlugin)
		return gvisorPlugin
	})
}

func main() {}
