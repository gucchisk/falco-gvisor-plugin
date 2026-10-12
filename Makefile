SHELL := /bin/bash
GO ?= go
OUTPUT := libgvisor.so

.PHONY: all build test generate clean

all: build

# Falco がロードする共有ライブラリをビルドする (Linux 上で実行すること)
build:
	CGO_ENABLED=1 $(GO) build -buildmode=c-shared -o $(OUTPUT) ./plugin

test:
	$(GO) test ./...

# syscall 番号 → 名前テーブルを golang.org/x/sys から再生成する
generate:
	$(GO) generate ./pkg/gvisor/

clean:
	rm -f $(OUTPUT) libgvisor.h
