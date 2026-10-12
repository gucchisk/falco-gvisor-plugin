# falco-gvisor-plugin

gVisor の [Runtime Monitoring](https://gvisor.dev/docs/user_guide/runtime_monitoring/) (remote sink) から送られる syscall イベントを Falco に取り込む Falco プラグインです。

```
┌────────────── gVisor sandbox ──────────────┐
│  app ──syscall──▶ Sentry ── trace points ──┼──▶ unix socket (SOCK_SEQPACKET) ──▶ libgvisor.so ──▶ Falco rules
└────────────────────────────────────────────┘      /run/falco/gvisor.sock          (source: gvisor)
```

- イベントソース名: `gvisor`
- プラグイン機能: event sourcing + field extraction

## 提供フィールド

| フィールド | 型 | 説明 |
|---|---|---|
| `proc.name` | string | イベントを発生させたプロセスの実行ファイル名 (Falco の `proc.name` と同等)。trace session で `process_name` context field の指定が必要 |
| `evt.type` | string | syscall 名 (Falco の `evt.type` と同等。例: `openat`, `execve`, `connect`)。syscall 以外の trace point では `sentry_clone`, `container_start` など |
| `evt.dir` | string | `>` = syscall の enter、`<` = syscall の exit (Falco の `evt.dir` と同等)。syscall 以外の trace point では値なし |
| `gvisor.sysno` | uint64 | gVisor が報告した syscall 番号 |
| `gvisor.container_id` | string | コンテナ ID (`container_id` context field が必要) |
| `gvisor.pid` | uint64 | サンドボックス内の PID (`group_id` context field が必要) |
| `gvisor.tid` | uint64 | サンドボックス内の TID (`thread_id` context field が必要) |

`evt.type` は gVisor のメッセージに含まれる syscall 番号を、ホストアーキテクチャ (amd64 / arm64) の syscall テーブルで名前に変換して求めます。テーブルにない番号の場合はメッセージ種別名 (例: `MESSAGE_SYSCALL_OPEN` → `open`) にフォールバックします。

## ビルド

Linux 上で実行してください (cgo を使用するため)。

```sh
make build   # libgvisor.so を生成
make test    # テスト
```

syscall テーブル (`pkg/gvisor/syscalltable_*.go`) は `golang.org/x/sys` から生成しています。更新する場合は `make generate` を実行します。

## 使い方

1. `libgvisor.so` を `/usr/share/falco/plugins/` に配置し、[examples/falco.yaml](examples/falco.yaml) を参考に Falco にプラグインを登録します。

   | init_config | デフォルト | 説明 |
   |---|---|---|
   | `socketPath` | `/run/falco/gvisor.sock` | gVisor が接続してくるソケットのパス |
   | `maxEventSize` | `65536` | 1 メッセージの最大サイズ (超えたものは破棄) |

   `open_params` を指定した場合は `socketPath` より優先されます。

2. ルールは `source: gvisor` を指定して書きます。例: [examples/gvisor_rules.yaml](examples/gvisor_rules.yaml)

   ```yaml
   - rule: Shell Executed In gVisor Sandbox
     condition: evt.type in (execve, execveat) and evt.dir = > and proc.name in (bash, sh)
     output: "proc.name=%proc.name evt.type=%evt.type evt.dir=%evt.dir"
     priority: NOTICE
     source: gvisor
   ```

3. Falco を起動してソケットが作成された後、[examples/pod-init.json](examples/pod-init.json) を指定して runsc を起動します。sink の `endpoint` は `socketPath` と一致させてください。

   ```sh
   runsc --pod-init-config=examples/pod-init.json ...
   ```

   `proc.name` を取得するには、各 trace point の `context_fields` に `process_name` を含める必要があります。trace point 名は `runsc trace metadata` で確認できます。特定の trace point がない syscall は `syscall/sysno/<番号>/enter` (raw syscall) で取得できます。

## 注意事項

- **`context_fields` は必須です。** gVisor は point ごとに指定された context field しか送りません。省略すると `proc.name` などが空になり、イベントのタイムスタンプも受信した時刻になります (`time` を指定した場合は gVisor 側の時刻)。
- **起動順序に注意してください。** runsc はサンドボックスの起動時に一度だけ sink に接続し、再接続はしません。Falco より先に runsc を起動すると、サンドボックスの起動が失敗します (sink に `"ignore_setup_error": true` を指定した場合は、イベントが送られないまま起動します)。Falco を再起動した場合は、サンドボックスも再起動する必要があります。
- 同じ syscall で enter と exit の両方の point を有効にすると、1 回の呼び出しで 2 イベント届きます。ルールでは `evt.dir` で絞り込んでください。
- `syscall/sysno/<番号>` の番号はアーキテクチャ依存です (例: `105` は arm64 では `init_module`、amd64 では `setuid`)。プラグインもホストのアーキテクチャのテーブルで `evt.type` に変換します。
- `proc.name` / `evt.type` / `evt.dir` はこのプラグインが `gvisor` ソース向けに定義するフィールドです。Falco 標準の `syscall` ソースのフィールドとは別物で、`proc.pname` や `fd.name` などは使用できません。
- Falco 本体にも gVisor 対応 (falco.yaml の `engine.kind: gvisor`) があり、そちらは `syscall` ソースとして標準ルールをそのまま使えます。このプラグインは、独自ソースとして gVisor のイベントを扱いたい場合向けです。
- プラグイン ID `999` は Falco のプラグインレジストリで開発・テスト用に予約されている ID です。公開・配布する場合は [registry](https://github.com/falcosecurity/plugins/blob/main/registry.yaml) で ID を取得してください。
