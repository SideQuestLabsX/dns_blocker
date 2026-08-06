# Zero-allocation DNS filtering daemon
#
# Links static musl and, for the encrypted profile, mbedTLS. Deliberately not
# freestanding, which -nostdlib would break

ARCH    ?= x86_64
# minimal | encrypted
PROFILE ?= encrypted
BUILD   ?= build/$(ARCH)-$(PROFILE)
TARGET  := $(BUILD)/dns_blocker

CC      ?= gcc

# -fstack-protector-strong is mandatory, the binary parses attacker-controlled
# length-prefixed data
CFLAGS_COMMON := \
	-std=c11 -O2 -flto \
	-fstack-protector-strong \
	-fno-unwind-tables -fno-asynchronous-unwind-tables \
	-Wall -Wextra -Wpedantic -Wshadow -Wconversion \
	-Isrc

# 32-bit ARM musl has no -static-pie. gcc accepts the flag and emits a dynamic
# binary, so those targets link -static and lose ASLR. Measured on the
# cross-tools toolchain and on Alpine, which agree. The 64-bit targets keep
# -static-pie. assert_static below rejects a dynamic result either way
#
# ARMv6 (Pi Zero W / ARM1176): no movw/movt, no NEON, unaligned access unsafe.
# Read multi-byte DNS fields byte-wise regardless of target.
ifeq ($(ARCH),x86_64)
  CFLAGS_ARCH := -m64 -static-pie
else ifeq ($(ARCH),aarch64)
  CFLAGS_ARCH := -march=armv8-a -static-pie
else ifeq ($(ARCH),armv7)
  CFLAGS_ARCH := -march=armv7-a -mfloat-abi=hard -mfpu=vfpv3-d16 -static
else ifeq ($(ARCH),armv6)
  CFLAGS_ARCH := -march=armv6 -mfloat-abi=hard -mfpu=vfp -static
else
  $(error Unknown ARCH '$(ARCH)'. Use: x86_64 aarch64 armv7 armv6)
endif

ifeq ($(PROFILE),minimal)
  CFLAGS_PROFILE := -DPROFILE_MINIMAL=1
  LIBS :=
else ifeq ($(PROFILE),encrypted)
  # MBEDTLS_MEMORY_BUFFER_ALLOC_C points mbedTLS at the boot arena, so the
  # zero-heap guarantee survives
  CFLAGS_PROFILE := -DPROFILE_ENCRYPTED=1 -DFEATURE_DOH=1 -DFEATURE_DOT=1
  LIBS := -lmbedtls -lmbedx509 -lmbedcrypto
else
  $(error Unknown PROFILE '$(PROFILE)'. Use: minimal | encrypted)
endif

# Off by default on purpose
# FEATURES += -DFEATURE_DGA_FILTER=1
# FEATURES += -DFEATURE_IO_URING=1     # opt-in only, pulls in liburing

CFLAGS  := $(CFLAGS_COMMON) $(CFLAGS_ARCH) $(CFLAGS_PROFILE) $(FEATURES)

SRC := $(wildcard src/*.c)
OBJ := $(patsubst src/%.c,$(BUILD)/%.o,$(SRC))
DEP := $(OBJ:.o=.d)

# A cross compiler has a matching readelf beside it, so prefer that name. Two
# cases need the fallback: make sets CC to cc by default, and a wrapper such as
# musl-gcc has no musl-readelf. Host readelf reads a foreign ELF header, so the
# fallback stays correct for a cross build
READELF_GUESS := $(if $(filter %gcc,$(CC)),$(patsubst %gcc,%readelf,$(CC)),readelf)
READELF ?= $(shell command -v $(READELF_GUESS) >/dev/null 2>&1 \
             && echo $(READELF_GUESS) || echo readelf)

# Some toolchains accept a static link flag and still produce a dynamic binary.
# The compiler reports no error, and the result needs a loader on the target.
# Examine the linked output
define assert_static
	@if ! $(READELF) --version >/dev/null 2>&1; then \
		echo "$(READELF) not found, cannot verify that $(1) is static"; \
		rm -f $(1); \
		exit 1; \
	fi
	@if $(READELF) -l $(1) | grep -q INTERP; then \
		echo "$(1): dynamically linked. $(CC) ignored the static link flag"; \
		rm -f $(1); \
		exit 1; \
	fi
endef

.PHONY: all check clean tools test test-static test-static-run fuzz fuzz-quick
all: $(TARGET)

$(TARGET): $(OBJ)
	@test -n "$(strip $(SRC))" || { echo "No sources in src/ yet"; exit 1; }
	$(CC) $(CFLAGS) $(OBJ) -o $@ $(LIBS)
	$(call assert_static,$@)
	@echo "built $@"

# Compiles domain lists into the trie the daemon maps. Host tool, so it is not
# built with the shipped flags
tools: $(BUILD)/mkblocklist
$(BUILD)/mkblocklist: tools/mkblocklist.c src/blocklist.c src/wire.c $(HDR) | $(BUILD)
	$(CC) -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Isrc $(filter %.c,$^) -o $@

# Health probe binary run by a supervisor. Keep it tiny
check: $(BUILD)/dns_blocker.check
$(BUILD)/dns_blocker.check: tools/check.c | $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_ARCH) $< -o $@
	$(call assert_static,$@)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

# Host tests. Sanitizers are incompatible with -static-pie, so these do not
# share CFLAGS with the shipped binary
TEST_CFLAGS := -std=c11 -O1 -g \
	-fsanitize=address,undefined -fno-omit-frame-pointer \
	-Wall -Wextra -Wpedantic -Wshadow -Wconversion \
	-Isrc

# These compile and link in one command, so -MMD would scatter depfiles. Depend
# on every header instead: a stale test binary reports PASS for code that is no
# longer there
HDR := $(wildcard src/*.h)

test: $(BUILD)/wire_test $(BUILD)/cache_test $(BUILD)/msg_test $(BUILD)/verify_test $(BUILD)/blocklist_test $(BUILD)/server_test $(BUILD)/fuzz_quick
	@$(BUILD)/wire_test
	@$(BUILD)/cache_test
	@$(BUILD)/msg_test
	@$(BUILD)/verify_test
	@$(BUILD)/blocklist_test
	@$(BUILD)/server_test
	@$(BUILD)/fuzz_quick 50000

$(BUILD)/wire_test: tests/wire_test.c src/wire.c $(HDR) | $(BUILD)
	$(CC) $(TEST_CFLAGS) $(filter %.c,$^) -o $@

$(BUILD)/cache_test: tests/cache_test.c src/cache.c src/wire.c src/arena.c $(HDR) | $(BUILD)
	$(CC) $(TEST_CFLAGS) $(filter %.c,$^) -o $@

$(BUILD)/msg_test: tests/msg_test.c src/msg.c src/wire.c $(HDR) | $(BUILD)
	$(CC) $(TEST_CFLAGS) $(filter %.c,$^) -o $@

$(BUILD)/verify_test: tests/verify_test.c src/verify.c src/wire.c $(HDR) | $(BUILD)
	$(CC) $(TEST_CFLAGS) $(filter %.c,$^) -o $@

$(BUILD)/blocklist_test: tests/blocklist_test.c src/blocklist.c src/wire.c $(HDR) | $(BUILD)
	$(CC) $(TEST_CFLAGS) $(filter %.c,$^) -o $@

# Binds loopback sockets and drives a real query through the whole path
$(BUILD)/server_test: tests/server_test.c src/server.c src/upstream.c src/msg.c src/cache.c src/verify.c src/blocklist.c src/wire.c src/arena.c $(HDR) | $(BUILD)
	$(CC) $(TEST_CFLAGS) -DCFG_UPSTREAM_TIMEOUT_MS=120 $(filter %.c,$^) -o $@ -lpthread

# Sanitizer-free copies of the pure tests, built with the shipped flags so they
# cross-compile and run under qemu-user on the target instruction set. This is
# the only way the byte-wise field reads get exercised on real ARM
XTEST := $(BUILD)/wire_test_native $(BUILD)/cache_test_native $(BUILD)/msg_test_native $(BUILD)/verify_test_native $(BUILD)/blocklist_test_native

test-static: $(XTEST)

test-static-run: $(XTEST)
	@for t in $(XTEST); do $(RUNNER) $$t || exit 1; done

$(BUILD)/wire_test_native: tests/wire_test.c src/wire.c $(HDR) | $(BUILD)
	$(CC) $(CFLAGS) $(filter %.c,$^) -o $@

$(BUILD)/cache_test_native: tests/cache_test.c src/cache.c src/wire.c src/arena.c $(HDR) | $(BUILD)
	$(CC) $(CFLAGS) $(filter %.c,$^) -o $@

$(BUILD)/msg_test_native: tests/msg_test.c src/msg.c src/wire.c $(HDR) | $(BUILD)
	$(CC) $(CFLAGS) $(filter %.c,$^) -o $@

$(BUILD)/verify_test_native: tests/verify_test.c src/verify.c src/wire.c $(HDR) | $(BUILD)
	$(CC) $(CFLAGS) $(filter %.c,$^) -o $@

$(BUILD)/blocklist_test_native: tests/blocklist_test.c src/blocklist.c src/wire.c $(HDR) | $(BUILD)
	$(CC) $(CFLAGS) $(filter %.c,$^) -o $@

# Coverage-blind driver for the same entry point, so the fuzz target is
# exercised on any toolchain with a sanitizer
fuzz-quick: $(BUILD)/fuzz_quick
	@$(BUILD)/fuzz_quick

$(BUILD)/fuzz_quick: tests/fuzz_standalone.c tests/fuzz_wire.c src/wire.c src/cache.c src/verify.c src/arena.c $(HDR) | $(BUILD)
	$(CC) $(TEST_CFLAGS) $(filter %.c,$^) -o $@

# libFuzzer needs clang. Run the binary directly, optionally with -max_total_time
FUZZ_CC ?= clang

fuzz: $(BUILD)/fuzz_wire
	@echo "run: $(BUILD)/fuzz_wire -max_total_time=60"

$(BUILD)/fuzz_wire: tests/fuzz_wire.c src/wire.c src/cache.c src/verify.c src/arena.c $(HDR) | $(BUILD)
	$(FUZZ_CC) -std=c11 -O1 -g -fsanitize=fuzzer,address,undefined -Isrc $(filter %.c,$^) -o $@

$(BUILD):
	@mkdir -p $(BUILD)

clean:
	@rm -rf build

-include $(DEP)
