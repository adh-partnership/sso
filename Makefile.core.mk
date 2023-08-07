FINDFILES=find . \( -path ./.git -o -path ./out -o -path ./.github -o -path ./vendor -o -path ./frontend/node_modules \) -prune -o -type f
XARGS=xargs -0 -r
RELEASE_LDFLAGS='-extldflags -static -s -w'
BINARIES=./cmd/api

lint-copyright:
	@${FINDFILES} \( -name '*.go' -o -name '*.sh' \) \( ! \( -name '*.gen.go' -o -name '*.pb.go' \) \) -print0 |\
		${XARGS} scripts/lint-copyright-license.sh

lint-go:
	@${FINDFILES} -name '*.go' \( ! \( -name '*.gen.go' -o -name '*.pb.go' \) \) -print0 | ${XARGS} scripts/lint_go.sh

lint-markdown:
	@${FINDFILES} -name '*.md' -print0 | ${XARGS} mdl --ignore-front-matter --style .mdl.rb

lint: lint-copyright lint-go lint-markdown

fix-copyright:
	@${FINDFILES} \( -name '*.go' -o -name '*.sh' \) \( ! \( -name '*.gen.go' -o -name '*.pb.go' \) \) -print0 |\
		${XARGS} scripts/fix-copyright-license.sh

.PHONY: default
default: init build

.PHONY: init
init:
	@mkdir -p out

.PHONY: build
build:
	@LDFLAGS=${RELEASE_LDFLAGS} scripts/build-go.sh out/ ${BINARIES}
	@cp -r static out/

.PHONY: mod-vendor
mod-vendor:
	@go mod vendor

.PHONY: dev
dev:
	@go run ./cmd/sso/main.go server

.PHONY: clean
clean:
	@rm -rf out

.PHONY: dist-clean
dist-clean: clean
	@rm -rf vendor
