.PHONY: linux linux-ci

linux:
	cargo build --release --features platform-linux
	bash scripts/linux/package.sh

linux-ci: linux

