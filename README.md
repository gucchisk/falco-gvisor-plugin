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

1. `libgvisor.so` を `/usr/share/falco/plugins/` に配置し、[examples/falco.yaml](examples/falco.yaml) を `/etc/falco/config.d/` に置いて Falco にプラグインを登録します。config.d のリスト (`plugins` / `load_plugins` / `rules_files`) は `falco.yaml` に追記されるので、ルールファイルは `rules.d` 以外の場所に置いても読み込まれます。

   | init_config | デフォルト | 説明 |
   |---|---|---|
   | `socketPath` | `/run/falco/gvisor.sock` | gVisor が接続してくるソケットのパス |
   | `maxEventSize` | `65536` | 1 メッセージの最大サイズ (超えたものは破棄) |

   `open_params` を指定した場合は `socketPath` より優先されます。

2. ルールは `source: gvisor` を指定して書きます。例: [examples/gvisor_rules.yaml](examples/gvisor_rules.yaml)

   ```yaml
   - rule: Shell Spawned In gVisor Sandbox
     condition: evt.type in (execve, execveat) and proc.name in (bash, sh)
     output: "proc.name=%proc.name evt.type=%evt.type"
     priority: NOTICE
     source: gvisor
   ```

   Falco はルールに一致したイベントしか出力しません。gVisor から届いた全イベントをログで確認したい場合は、[examples/gvisor_log_all_rules.yaml](examples/gvisor_log_all_rules.yaml) も読み込んでください (全イベントに一致する DEBUG ルール)。

3. Falco を起動してソケットが作成された後、[examples/pod-init.json](examples/pod-init.json) を指定して runsc を起動します。sink の `endpoint` は `socketPath` と一致させてください。

   ```sh
   runsc --pod-init-config=examples/pod-init.json ...
   ```

   `proc.name` を取得するには、各 trace point の `context_fields` に `process_name` を含める必要があります。trace point 名は `runsc trace metadata` で確認できます。特定の trace point がない syscall は `syscall/sysno/<番号>/exit` (raw syscall) で取得できます。

   Falco 0.45 と同様に、**exit point だけを有効にする**ことを推奨します (例の `pod-init.json` も exit のみ)。Falco 0.45 は syscall の enter イベントを廃止しました。`evt.dir` は廃止済みのフィールドとして扱われ、ルールで使うと `evt.dir = >` は常に false に書き換えられます。そのため、このプラグインも方向を表すフィールドは提供しません。

## 注意事項

- **`context_fields` は必須です。** gVisor は point ごとに指定された context field しか送りません。省略すると `proc.name` などが空になり、イベントのタイムスタンプも受信した時刻になります (`time` を指定した場合は gVisor 側の時刻)。
- **起動順序に注意してください。** runsc はサンドボックスの起動時に一度だけ sink に接続し、再接続はしません。Falco より先に runsc を起動すると、サンドボックスの起動が失敗します (sink に `"ignore_setup_error": true` を指定した場合は、イベントが送られないまま起動します)。Falco を再起動した場合は、サンドボックスも再起動する必要があります。
- 同じ syscall で enter と exit の両方の point を有効にすると、1 回の呼び出しで 2 イベント届き、ルールも 2 回発火します。exit point だけを使ってください。
- **ソケットの置き場所**: Falco の systemd ユニットに `PrivateTmp=true` が設定されていると、`/tmp` に作ったソケットは runsc から見えません。`/run` 配下 (例: `/run/gvisor_events.sock`) に置いてください。
- `gvisor_log_all_rules.yaml` は全イベントを出力するため、件数が非常に多くなります (特に openat や dup)。journald のレート制限 (`RateLimitBurst`) によって取りこぼすことがあります。
- `syscall/sysno/<番号>` の番号はアーキテクチャ依存です (例: `105` は arm64 では `init_module`、amd64 では `setuid`)。プラグインもホストのアーキテクチャのテーブルで `evt.type` に変換します。
- `proc.name` / `evt.type` はこのプラグインが `gvisor` ソース向けに定義するフィールドです。Falco 標準の `syscall` ソースのフィールドとは別物で、`proc.pname` や `fd.name` などは使用できません。
- Falco 本体にも gVisor 対応 (falco.yaml の `engine.kind: gvisor`) があり、そちらは `syscall` ソースとして標準ルールをそのまま使えます。このプラグインは、独自ソースとして gVisor のイベントを扱いたい場合向けです。
- プラグイン ID `999` は Falco のプラグインレジストリで開発・テスト用に予約されている ID です。公開・配布する場合は [registry](https://github.com/falcosecurity/plugins/blob/main/registry.yaml) で ID を取得してください。
