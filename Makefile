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

# Link flags
LDFLAGS := -lelf -lz -lbpf -lcap

# eBPF compiler flags
BPF_CFLAGS := -target bpf -D__TARGET_ARCH_x86 -Wall -O2 -g
BPF_CFLAGS += -I$(EBPF_DIR) -I$(BUILD_DIR)

# Static linking option (can be enabled with STATIC=1)
ifdef STATIC
    LDFLAGS := -lbpf -lelf -lz -lcap -static
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
test-unit: $(EBPF_SKELETONS)
	@echo "Running unit tests..."
	@$(MAKE) run-unit-tests

# Filter out main.c from sources to avoid multiple main() definitions
MAIN_SOURCES_NO_MAIN := $(filter-out $(SRC_DIR)/main.c,$(MAIN_SOURCES))

# Build and run each unit test separately
.PHONY: run-unit-tests
run-unit-tests:
	@for test_file in $(UNIT_TEST_SOURCES); do \
		test_name=$$(basename $$test_file .c); \
		echo "Building and running $$test_name..."; \
		$(CC) $(CFLAGS) $$test_file $(MAIN_SOURCES_NO_MAIN) -o $(BUILD_DIR)/$$test_name $(LDFLAGS) 2>&1 | grep -v "warning:" || true; \
		if [ -f $(BUILD_DIR)/$$test_name ]; then \
			$(BUILD_DIR)/$$test_name || exit 1; \
			echo ""; \
		else \
			echo "Failed to build $$test_name"; \
			exit 1; \
		fi; \
	done

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
	@echo "Installing crypto-tracer..."
	install -D -m 755 $(BUILD_DIR)/$(PROJECT_NAME) $(DESTDIR)/usr/bin/$(PROJECT_NAME)
	@echo "Installing man page..."
	install -D -m 644 crypto-tracer.1 $(DESTDIR)/usr/share/man/man1/crypto-tracer.1
	@if command -v mandb >/dev/null 2>&1; then \
		mandb -q 2>/dev/null || true; \
	fi
	@echo "Installation complete!"
	@echo ""
	@echo "To run without sudo, grant capabilities:"
	@echo "  sudo setcap cap_bpf,cap_perfmon+ep /usr/bin/$(PROJECT_NAME)"
	@echo ""
	@echo "View man page:"
	@echo "  man crypto-tracer"

# Uninstall target
.PHONY: uninstall
uninstall:
	@echo "Uninstalling crypto-tracer..."
	rm -f $(DESTDIR)/usr/bin/$(PROJECT_NAME)
	rm -f $(DESTDIR)/usr/share/man/man1/crypto-tracer.1
	@if command -v mandb >/dev/null 2>&1; then \
		mandb -q 2>/dev/null || true; \
	fi
	@echo "Uninstallation complete!"

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

# Package target - create distributable tarball
.PHONY: package
package: $(BUILD_DIR)/$(PROJECT_NAME)
	@echo "Creating distribution package..."
	@mkdir -p $(BUILD_DIR)/package/$(PROJECT_NAME)-$(VERSION)
	@cp $(BUILD_DIR)/$(PROJECT_NAME) $(BUILD_DIR)/package/$(PROJECT_NAME)-$(VERSION)/
	@cp crypto-tracer.1 $(BUILD_DIR)/package/$(PROJECT_NAME)-$(VERSION)/
	@cp README.md $(BUILD_DIR)/package/$(PROJECT_NAME)-$(VERSION)/
	@cp DEMO.md $(BUILD_DIR)/package/$(PROJECT_NAME)-$(VERSION)/
	@cp TROUBLESHOOTING.md $(BUILD_DIR)/package/$(PROJECT_NAME)-$(VERSION)/
	@cp LICENSE $(BUILD_DIR)/package/$(PROJECT_NAME)-$(VERSION)/
	@cd $(BUILD_DIR)/package && tar czf $(PROJECT_NAME)-$(VERSION).tar.gz $(PROJECT_NAME)-$(VERSION)
	@echo "Package created: $(BUILD_DIR)/package/$(PROJECT_NAME)-$(VERSION).tar.gz"

# Package static binary for distribution
.PHONY: package-static
package-static: clean
	@echo "Building static binary for distribution..."
	@$(MAKE) static
	@$(MAKE) package
	@echo "Static package created: $(BUILD_DIR)/package/$(PROJECT_NAME)-$(VERSION).tar.gz"

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
	@echo "  install          Install the program and man page"
	@echo "  uninstall        Uninstall the program and man page"
	@echo "  package          Create distribution tarball"
	@echo "  package-static   Create static binary distribution"
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
	@echo "  DESTDIR=path     Installation prefix (default: /)"

# Ensure eBPF objects depend on common header
$(EBPF_OBJECTS): $(EBPF_DIR)/common.h

# Phony targets
.PHONY: all clean install uninstall check-deps config debug static help test test-unit test-integration