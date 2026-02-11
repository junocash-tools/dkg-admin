BIN := bin/dkg-admin

.PHONY: build
build:
	cargo build --release
	mkdir -p bin
	cp target/release/dkg-admin $(BIN)

.PHONY: test
test:
	cargo test

.PHONY: test-e2e
test-e2e:
	cargo test --test e2e_txsign_ext -- --ignored --nocapture

.PHONY: test-all
test-all: test test-e2e

.PHONY: fmt
fmt:
	cargo fmt

.PHONY: lint
lint:
	cargo clippy -- -D warnings
