export TOCK_KERNEL_VERSION := $(shell git describe --always 2> /dev/null || echo "1.3+")

ifndef DEBUG
CARGO_FLAGS += --release
endif

all: kernel

kernel:
	cargo build $(CARGO_FLAGS)

run:
	cargo run $(CARGO_FLAGS)
