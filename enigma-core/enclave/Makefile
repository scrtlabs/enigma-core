
Rust_Enclave_Name := libenclave.a
Rust_Enclave_Files := $(wildcard src/*.rs)
CARGO_FLAGS := --release
CARGO_FLAGS += $(if $(JOBS), -j$(JOBS), )

.PHONY: all

all: $(Rust_Enclave_Name)

$(Rust_Enclave_Name): $(Rust_Enclave_Files)
ifeq ($(XARGO_SGX), 1)
	RUST_TARGET_PATH=$(shell pwd) xargo build --target x86_64-unknown-linux-sgx $(CARGO_FLAGS)
	cp ./target/x86_64-unknown-linux-sgx/release/libenigmacoreenclave.a ../lib/libenclave.a
else
	cargo build $(CARGO_FLAGS)
	cp ./target/release/libenigmacoreenclave.a ../lib/libenclave.a
endif