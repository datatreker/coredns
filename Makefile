# Makefile for building CoreDNS
GITCOMMIT:=$(shell git describe --dirty --always)
BINARY:=coredns
SYSTEM:=
CHECKS:=check
BUILDOPTS:=-v
GOPATH?=$(HOME)/go
MAKEPWD:=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))
CGO_ENABLED:=0

.ONESHELL:
APP_PROFILE ?= dev
ifdef $$APP_PROFILE
APP_PROFILE := $$APP_PROFILE
endif

.PHONY: all
all: coredns

.PHONY: coredns
coredns: $(CHECKS)
	CGO_ENABLED=$(CGO_ENABLED) $(SYSTEM) go build $(BUILDOPTS) -ldflags="-s -w -X github.com/coredns/coredns/coremain.GitCommit=$(GITCOMMIT)" -o $(BINARY)

.PHONY: check
check: core/plugin/zplugin.go core/dnsserver/zdirectives.go

core/plugin/zplugin.go core/dnsserver/zdirectives.go: plugin.cfg
	go generate coredns.go
	go get

.PHONY: gen
gen:
	go generate coredns.go
	go get

.PHONY: pb
pb:
	$(MAKE) -C pb

.PHONY: clean
clean:
	go clean
	rm -f coredns

.PHONY: run
run:
	go run coredns.go -conf deployment/$(APP_PROFILE)/Corefile
	@echo "coredns started."
