# falco-gvisor-plugin

gVisor の [Runtime Monitoring](https://gvisor.dev/docs/user_guide/runtime_monitoring/) (remote sink) から送られる syscall イベントを Falco に取り込む Falco プラグインです。

```
┌────────────── gVisor sandbox ──────────────┐
│  app ──syscall──▶ Sentry ── trace points ──┼──▶ unix socket (SOCK_SEQPACKET) ──▶ libgvisor.so ──▶ Falco rules
└────────────────────────────────────────────┘      /run/gvisor_events.sock      (プロセス表)    (source: gvisor)
```

- イベントソース名: `gvisor`
- プラグイン機能: event sourcing + field extraction

## 提供フィールド

Falco 標準ルールを流用できるよう、意味が同じフィールドは Falco と同じ名前にしています。値が取れない場合 (対象外の syscall、必要な context field がない場合など) は値なしになります。

### イベント (`evt.*`)

| フィールド | 型 | 説明 |
|---|---|---|
| `evt.type` | string | syscall 名 (例: `openat`, `execve`, `connect`)。syscall 以外の point では `sentry_clone`, `sentry_exec`, `container_start` など |
| `evt.res` | string | 成功なら `SUCCESS`、失敗ならエラー名 (例: `ENOENT`)。exit point のみ |
| `evt.rawres` | uint64 | 成功した syscall の戻り値。**失敗時は値なし** (プラグインは負の整数を返せないため。`evt.rawres >= 0` は失敗時に false になる) |
| `evt.failed` | bool | syscall が失敗したか |
| `evt.is_open_read` / `evt.is_open_write` | bool | open 系で読み込み / 書き込み用に開いたか |
| `evt.arg.flags` | string | open 系のフラグ (例: `O_WRONLY\|O_CREAT\|O_TRUNC`) |
| `evt.arg.request` | string | ptrace の request (例: `PTRACE_ATTACH`) |
| `evt.arg.domain` | string | socket のドメイン (例: `AF_PACKET`) |

### ファイルディスクリプタ (`fd.*`)

| フィールド | 型 | 説明 |
|---|---|---|
| `fd.num` | uint64 | fd 番号 (open 系は成功時の戻り値、connect は対象の fd、dup は複製元) |
| `fd.name` | string | open 系は絶対パス (相対パスは `cwd` context field / dirfd の `fd_path` で解決)。connect は接続先 (`IP:ポート` または unix ソケットのパス) |
| `fd.nameraw` | string | syscall に渡されたままのパス |
| `fd.directory` / `fd.filename` | string | ファイルのディレクトリ部分 / ファイル名部分 |
| `fd.type` / `fd.typechar` | string | `file`/`f`, `directory`/`d`, `ipv4`/`4`, `ipv6`/`6`, `unix`/`u`, `netlink`/`n` |
| `fd.sip` / `fd.rip` | ipaddr | connect の接続先 IP |
| `fd.sport` / `fd.rport` | uint64 | connect の接続先ポート |

### プロセス (`proc.*` など)

| フィールド | 型 | 説明 |
|---|---|---|
| `proc.pid` / `thread.tid` | uint64 | サンドボックス内の PID / TID |
| `proc.name` | string | 実行ファイル名 (15 文字で切り詰め)。execve イベントでは exec 後の名前 |
| `proc.exe` / `proc.exepath` | string | argv[0] / 実行ファイルのフルパス |
| `proc.args` / `proc.cmdline` | string | 引数 (argv[1:]) / `proc.name` + 引数 |
| `proc.cwd` | string | カレントディレクトリ |
| `proc.tty` | uint64 | 端末のデバイス番号の**近似値** (exec 時の標準入出力が `/dev/pts/N` などなら、その番号) |
| `proc.is_exe_upper_layer` | bool | 実行ファイルがコンテナの書き込み層にある (イメージに含まれない) か |
| `proc.is_exe_from_memfd` | bool | memfd から実行されたか (ファイルレス実行) |
| `proc.stdin.type` / `proc.stdout.type` / `proc.stderr.type` | string | exec 時の標準入出力の種類 (`fd.type` と同じ表記。`pipe` もある) |
| `proc.ppid` / `proc.pname` / `proc.pexe` / `proc.pexepath` / `proc.pcmdline` | | 親プロセスの PID / 名前 / argv[0] / パス / コマンドライン |
| `proc.aname[N]` / `proc.apid[N]` / `proc.aexepath[N]` | | N 世代上の祖先 (1 = 親、2 = 祖父母 …、0 = 自分)。**インデックスは必須** |
| `user.uid` / `group.gid` | uint64 | 実効 UID / GID |

### gVisor 固有 (`gvisor.*`)

| フィールド | 型 | 説明 |
|---|---|---|
| `gvisor.anames` | string (list) | 全祖先の名前。Falco の `proc.aname in (a, b)` は `gvisor.anames intersects (a, b)` と書く |
| `gvisor.is_exec_session` | bool | `runsc exec` (kubectl exec) で作られたプロセス、またはその子孫か |
| `gvisor.sysno` | uint64 | gVisor が報告した syscall 番号 |
| `gvisor.container_id` | string | コンテナ ID |
| `gvisor.pid` / `gvisor.tid` | uint64 | `proc.pid` / `thread.tid` と同じ (互換用) |

`evt.type` は gVisor のメッセージに含まれる syscall 番号を、ホストアーキテクチャ (amd64 / arm64) の syscall テーブルで名前に変換して求めます。テーブルにない番号の場合はメッセージ種別名 (例: `MESSAGE_SYSCALL_OPEN` → `open`) にフォールバックします。

### プロセス表

`proc.pname` や `proc.cmdline` などの値は、gVisor のイベント 1 件には含まれません。そのためプラグインは、次の point からサンドボックスごとにプロセス表を作ります。

| point | 用途 |
|---|---|
| `container/start` | コンテナの最初のプロセス |
| `sentry/clone` | 子プロセスの作成 (親の情報を引き継ぐ) |
| `sentry/execve` | 実行ファイル・引数の更新。`binary_info` (書き込み層・memfd の判定) と `fd_info` (標準入出力・tty) の optional field も使う |
| `sentry/task_exit` | プロセスの終了 |

受信した時点のプロセス情報 (自分と最大 16 世代の祖先) を、gVisor のメッセージの前に付けて Falco に渡します。フィールド抽出時はこの情報だけを使うため、Falco のキャプチャファイルを再生しても同じ結果になります。`runsc exec` で作られたプロセスには clone / execve の point が届かないため、最初のイベントの context field (`process_name`, `parent_thread_group_id` など) から作ります。

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
   | `socketPath` | `/run/falco/gvisor.sock` | gVisor が接続してくるソケットのパス (親ディレクトリは事前に作成しておくこと) |
   | `maxEventSize` | `65536` | gVisor の 1 メッセージの最大サイズ (超えたものは破棄)。Falco に渡すイベントは、これにプロセス情報 (最大 32KiB) を加えたサイズになる |

   `open_params` を指定した場合は `socketPath` より優先されます。

2. ルールは `source: gvisor` を指定して書きます。例: [examples/gvisor_rules.yaml](examples/gvisor_rules.yaml)

   通常のコンテナと同じ条件で検知したい場合は、Falco 標準ルールを移植した [examples/gvisor_falco_rules.yaml](examples/gvisor_falco_rules.yaml) だけを読み込みます。`gvisor_rules.yaml` は標準ルールにない独自のサンプル (シェルの起動をすべて検知するなど) のため、読み込むと通常のコンテナでは出ないログが出ます。

   ```yaml
   - rule: Shell Spawned In gVisor Sandbox
     condition: evt.type in (execve, execveat) and proc.name in (bash, sh)
     output: "proc.name=%proc.name evt.type=%evt.type"
     priority: NOTICE
     source: gvisor
   ```

   Falco 標準ルールのうち、このプラグインのフィールドで判定できるものを移植したルールが [examples/gvisor_falco_rules.yaml](examples/gvisor_falco_rules.yaml) にあります (19 ルール)。標準ルールと同時に読み込めるよう、ルール・マクロ・リストの名前は gVisor 用に変えています。省いた条件は各ルールのコメントを参照してください。

   Falco はルールに一致したイベントしか出力しません。gVisor から届いた全イベントをログで確認したい場合は、[examples/gvisor_log_all_rules.yaml](examples/gvisor_log_all_rules.yaml) も読み込んでください (全イベントに一致する DEBUG ルール)。

3. Falco を起動してソケットが作成された後、[examples/pod-init.json](examples/pod-init.json) を指定して runsc を起動します。sink の `endpoint` は `socketPath` と一致させてください。

   ```sh
   runsc --pod-init-config=examples/pod-init.json ...
   ```

   例の `pod-init.json` は、プロセス表用の point (`container/start`, `sentry/clone`, `sentry/execve`, `sentry/task_exit`) と、context field `time`, `container_id`, `thread_id`, `group_id`, `process_name`, `cwd`, `credentials`, `parent_thread_group_id`, `is_exec_session` を有効にしています。これらを省くと、対応するフィールドが値なしになります。trace point 名は `runsc trace metadata` で確認できます。特定の trace point がない syscall は `syscall/sysno/<番号>/exit` (raw syscall) で取得できます。

   Falco 0.45 と同様に、**exit point だけを有効にする**ことを推奨します (例の `pod-init.json` も exit のみ)。Falco 0.45 は syscall の enter イベントを廃止しました。`evt.dir` は廃止済みのフィールドとして扱われ、ルールで使うと `evt.dir = >` は常に false に書き換えられます。そのため、このプラグインも方向を表すフィールドは提供しません。

## 注意事項

- **`context_fields` は必須です。** gVisor は point ごとに指定された context field しか送りません。省略すると `proc.name` などが空になり、イベントのタイムスタンプも受信した時刻になります (`time` を指定した場合は gVisor 側の時刻)。
- **起動順序に注意してください。** runsc はサンドボックスの起動時に一度だけ sink に接続し、再接続はしません。Falco より先に runsc を起動すると、サンドボックスの起動が失敗します (sink に `"ignore_setup_error": true` を指定した場合は、イベントが送られないまま起動します)。Falco を再起動した場合は、サンドボックスも再起動する必要があります。
- 同じ syscall で enter と exit の両方の point を有効にすると、1 回の呼び出しで 2 イベント届き、ルールも 2 回発火します。exit point だけを使ってください。
- **ソケットの置き場所**: Falco の systemd ユニットに `PrivateTmp=true` が設定されていると、`/tmp` に作ったソケットは runsc から見えません。`/run` 配下 (例: `/run/gvisor_events.sock`) に置いてください。
- `gvisor_log_all_rules.yaml` は全イベントを出力するため、件数が非常に多くなります (特に openat や dup)。journald のレート制限 (`RateLimitBurst`) によって取りこぼすことがあります。
- `syscall/sysno/<番号>` の番号はアーキテクチャ依存です (例: `105` は arm64 では `init_module`、amd64 では `setuid`)。プラグインもホストのアーキテクチャのテーブルで `evt.type` に変換します。
- このプラグインのフィールドは `gvisor` ソース向けに定義したもので、Falco 標準の `syscall` ソースのフィールドとは別物です。名前が同じでも、上の表にないフィールド (`user.name`, `user.loginuid`, `container.image.*`, `k8s.*`, `thread.cap_effective`, `fd.l4proto` など) は使用できません。
- `proc.aname` はインデックスが必須です。Falco の `proc.aname in (...)` (いずれかの祖先) は `gvisor.anames intersects (...)` に書き換えてください。
- `proc.tty` は近似値です。gVisor は制御端末を報告しないため、exec 時の標準入出力のパスから推定しています。`kubectl exec -it` で直接起動したシェルには execve の point が届かないため、そのシェル自体の端末は分かりません (そのシェルから起動したプロセスには付きます)。
- `dup` イベントの `fd.type` は分かりません (gVisor が複製元のソケットの種類を報告しないため)。標準入出力をソケットにつなぐ検知は、exec 時の `proc.stdin.type` / `proc.stdout.type` で行います。
- raw syscall の point (`syscall/sysno/N`) は引数を数値でしか送らないため、symlinkat / linkat のパスなどは取得できません。
- 以前の Falco には本体の gVisor 対応 (falco.yaml の `engine.kind: gvisor`) がありましたが、Falco 0.45 では `engine.kind 'gvisor' is not a valid kind` となり使用できません。このプラグインはその代わりに、独自ソース `gvisor` として gVisor のイベントを扱います。
- プラグイン ID `999` は Falco のプラグインレジストリで開発・テスト用に予約されている ID です。公開・配布する場合は [registry](https://github.com/falcosecurity/plugins/blob/main/registry.yaml) で ID を取得してください。
