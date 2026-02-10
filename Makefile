BIN := bin/dkg-admin

.PHONY: build
build:
\tcargo build --release
\tmkdir -p bin
\tcp target/release/dkg-admin $(BIN)

.PHONY: test
test:
\tcargo test

.PHONY: fmt
fmt:
\tcargo fmt

.PHONY: lint
lint:
\tcargo clippy -- -D warnings
