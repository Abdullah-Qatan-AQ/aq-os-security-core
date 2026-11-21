.PHONY: test rust-test rust-kernel all

all: test rust-test rust-kernel

test:
	python3 test_aqos.py
	python3 test_aqos_hardening.py

rust-test:
	cargo test -p aqos-policy

rust-kernel:
	cargo run -p aqos-image
