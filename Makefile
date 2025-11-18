# Makefile for crypto-tracer
# Copyright (C) 2024

# Project configuration
PROJECT_NAME := crypto-tracer
VERSION := 1.0.0
BUILD_DIR := build
SRC_DIR := src
EBPF_DIR := $(SRC_DIR)/ebpf
INCLUDE_DIR := $(SRC_DIR)/include
TEST_DIR := tests

# Compiler and tool configuration
CC := gcc
CLANG := clang
BPFTOOL := bpftool
LLVM_STRIP := llvm-strip

# Compiler flags
CFLAGS := -Wall -Wextra -std=c11 -O2 -g
CFLAGS += -I$(INCLUDE_DIR) -I$(BUILD_DIR)
# Try to find libbpf headers in common locations
ifneq ($(wildcard /usr/src/linux-headers-$(shell uname -r)/tools/bpf/resolve_btfids/libbpf/include),)
    CFLAGS += -I/usr/src/linux-headers-$(shell uname -r)/tools/bpf/resolve_btfids/libbpf/include
endif
LDFLAGS := -L/usr/lib/x86_64-linux-gnu -lz -lcap
# Link directly to available library files
LDFLAGS += /usr/lib/x86_64-linux-gnu/libelf.so.1
LDFLAGS += /usr/lib/x86_64-linux-gnu/libbpf.so.0

# eBPF compiler flags
BPF_CFLAGS := -target bpf -D__TARGET_ARCH_x86 -Wall -O2 -g
BPF_CFLAGS += -I$(EBPF_DIR) -I$(BUILD_DIR)
# Try to find libbpf headers in common locations
BPF_CFLAGS += -I/usr/include
ifneq ($(wildcard /usr/src/linux-headers-$(shell uname -r)/tools/bpf/resolve_btfids/libbpf/include),)
    BPF_CFLAGS += -I/usr/src/linux-headers-$(shell uname -r)/tools/bpf/resolve_btfids/libbpf/include
endif

# Static linking option (can be enabled with STATIC=1)
ifdef STATIC
    LDFLAGS += -static
    CFLAGS += -DSTATIC_BUILD
endif

# Source files
MAIN_SOURCES := $(wildcard $(SRC_DIR)/*.c)
EBPF_SOURCES := $(wildcard $(EBPF_DIR)/*.bpf.c)
EBPF_OBJECTS := $(EBPF_SOURCES:$(EBPF_DIR)/%.bpf.c=$(BUILD_DIR)/%.bpf.o)
EBPF_SKELETONS := $(EBPF_SOURCES:$(EBPF_DIR)/%.bpf.c=$(BUILD_DIR)/%.skel.h)

# Test sources
UNIT_TEST_SOURCES := $(wildcard $(TEST_DIR)/unit/*.c)
INTEGRATION_TEST_SOURCES := $(wildcard $(TEST_DIR)/integration/*.c)

# Default target
.PHONY: all
all: $(BUILD_DIR)/$(PROJECT_NAME)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Generate vmlinux.h from running kernel (CO-RE strategy)
$(BUILD_DIR)/vmlinux.h: | $(BUILD_DIR)
	@echo "Generating vmlinux.h from running kernel..."
	@if command -v $(BPFTOOL) >/dev/null 2>&1; then \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@ 2>/dev/null || \
		(echo "Warning: Could not generate vmlinux.h from BTF, using fallback"; \
		 cp $(EBPF_DIR)/vmlinux_fallback.h $@); \
	else \
		echo "Warning: bpftool not found, using fallback vmlinux.h"; \
		cp $(EBPF_DIR)/vmlinux_fallback.h $@; \
	fi

# Create a symlink for eBPF programs to use
$(EBPF_DIR)/vmlinux.h: $(BUILD_DIR)/vmlinux.h
	@ln -sf ../../$(BUILD_DIR)/vmlinux.h $@

# Compile eBPF programs
$(BUILD_DIR)/%.bpf.o: $(EBPF_DIR)/%.bpf.c $(BUILD_DIR)/vmlinux.h $(EBPF_DIR)/vmlinux.h | $(BUILD_DIR)
	@echo "Compiling eBPF program: $<"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@if command -v $(LLVM_STRIP) >/dev/null 2>&1; then \
		$(LLVM_STRIP) -g $@; \
	fi

# Generate BPF skeletons
$(BUILD_DIR)/%.skel.h: $(BUILD_DIR)/%.bpf.o | $(BUILD_DIR)
	@echo "Generating skeleton: $@"
	@if command -v $(BPFTOOL) >/dev/null 2>&1; then \
		$(BPFTOOL) gen skeleton $< > $@; \
	else \
		echo "Error: bpftool is required for skeleton generation"; \
		echo "Please install bpftool or libbpf-dev package"; \
		exit 1; \
	fi

# Compile main program
$(BUILD_DIR)/$(PROJECT_NAME): $(MAIN_SOURCES) $(EBPF_SKELETONS) | $(BUILD_DIR)
	@echo "Compiling main program..."
	$(CC) $(CFLAGS) $(MAIN_SOURCES) -o $@ $(LDFLAGS)

# Build unit tests
.PHONY: test-unit
test-unit: $(BUILD_DIR)/test-unit

$(BUILD_DIR)/test-unit: $(UNIT_TEST_SOURCES) | $(BUILD_DIR)
	@echo "Compiling unit tests..."
	$(CC) $(CFLAGS) $(UNIT_TEST_SOURCES) -o $@ $(LDFLAGS)

# Build integration tests
.PHONY: test-integration
test-integration: $(BUILD_DIR)/test-integration

$(BUILD_DIR)/test-integration: $(INTEGRATION_TEST_SOURCES) | $(BUILD_DIR)
	@echo "Compiling integration tests..."
	$(CC) $(CFLAGS) $(INTEGRATION_TEST_SOURCES) -o $@ $(LDFLAGS)

# Run all tests
.PHONY: test
test: test-unit test-integration
	@echo "Running unit tests..."
	@$(BUILD_DIR)/test-unit
	@echo "Running integration tests..."
	@$(BUILD_DIR)/test-integration

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(EBPF_DIR)/vmlinux.h

# Install target
.PHONY: install
install: $(BUILD_DIR)/$(PROJECT_NAME)
	install -D -m 755 $(BUILD_DIR)/$(PROJECT_NAME) $(DESTDIR)/usr/bin/$(PROJECT_NAME)

# Uninstall target
.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)/usr/bin/$(PROJECT_NAME)

# Development helpers
.PHONY: check-deps
check-deps:
	@echo "Checking build dependencies..."
	@command -v $(CC) >/dev/null || (echo "Error: gcc not found" && exit 1)
	@command -v $(CLANG) >/dev/null || (echo "Error: clang not found" && exit 1)
	@command -v $(BPFTOOL) >/dev/null || echo "Warning: bpftool not found (skeleton generation will fail)"
	@command -v $(LLVM_STRIP) >/dev/null || echo "Warning: llvm-strip not found (eBPF programs won't be stripped)"
	@echo -n "Checking for libcap... "
	@echo "#include <sys/capability.h>" | $(CC) -E - >/dev/null 2>&1 && echo "found" || (echo "not found - install libcap-dev" && exit 1)
	@echo -n "Checking for libelf... "
	@echo "#include <libelf.h>" | $(CC) -E - >/dev/null 2>&1 && echo "found" || (echo "not found - install libelf-dev" && exit 1)
	@echo "Dependency check complete"

# Show build configuration
.PHONY: config
config:
	@echo "Build Configuration:"
	@echo "  Project: $(PROJECT_NAME) v$(VERSION)"
	@echo "  CC: $(CC)"
	@echo "  CLANG: $(CLANG)"
	@echo "  CFLAGS: $(CFLAGS)"
	@echo "  BPF_CFLAGS: $(BPF_CFLAGS)"
	@echo "  LDFLAGS: $(LDFLAGS)"
	@echo "  Static linking: $(if $(STATIC),enabled,disabled)"
	@echo "  Build directory: $(BUILD_DIR)"

# Debug target - compile with debug symbols and no optimization
.PHONY: debug
debug: CFLAGS := $(filter-out -O2,$(CFLAGS)) -O0 -DDEBUG
debug: BPF_CFLAGS := $(filter-out -O2,$(BPF_CFLAGS)) -O0
debug: $(BUILD_DIR)/$(PROJECT_NAME)

# Static build target
.PHONY: static
static:
	$(MAKE) STATIC=1

# Help target
.PHONY: help
help:
	@echo "crypto-tracer build system"
	@echo ""
	@echo "Targets:"
	@echo "  all              Build the main program (default)"
	@echo "  test             Build and run all tests"
	@echo "  test-unit        Build and run unit tests"
	@echo "  test-integration Build and run integration tests"
	@echo "  clean            Remove build artifacts"
	@echo "  install          Install the program"
	@echo "  uninstall        Uninstall the program"
	@echo "  check-deps       Check build dependencies"
	@echo "  config           Show build configuration"
	@echo "  debug            Build with debug symbols"
	@echo "  static           Build with static linking"
	@echo "  help             Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  STATIC=1         Enable static linking"
	@echo "  CC=compiler      Set C compiler (default: gcc)"
	@echo "  CLANG=compiler   Set Clang compiler (default: clang)"

# Ensure eBPF objects depend on common header
$(EBPF_OBJECTS): $(EBPF_DIR)/common.h

# Phony targets
.PHONY: all clean install uninstall check-deps config debug static help test test-unit test-integration