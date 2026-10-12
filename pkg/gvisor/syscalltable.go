package gvisor

// syscall 番号 → 名前のテーブルはアーキテクチャごとに生成する。
// gVisor が報告する syscall 番号はサンドボックスのアーキテクチャ (= ホストと同じ) のもの。
//go:generate go run ../../tools/gensyscalltable -arch amd64 -out syscalltable_amd64.go
//go:generate go run ../../tools/gensyscalltable -arch arm64 -out syscalltable_arm64.go
