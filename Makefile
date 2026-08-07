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
# mkblocklist runs on the build host and its output is linked into the daemon,
# so a cross build still needs a native compiler for it
HOSTCC  ?= gcc
MBEDTLS_DIR ?= $(BUILD)/mbedtls

# Domain list compiled into .rodata as the cold-boot fallback. Set it empty to
# link the zero-length stub and ship without one
EMBED_LIST ?= blocklists/embedded.txt

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

MBEDTLS_CFLAGS := -O2 -fstack-protector-strong \
	-fno-unwind-tables -fno-asynchronous-unwind-tables \
	$(filter-out -static -static-pie,$(CFLAGS_ARCH))
MBEDTLS_CC_ID := $(shell $(CC) --version 2>/dev/null | head -n 1)
MBEDTLS_AR_ID := $(shell $(AR) --version 2>/dev/null | head -n 1)
MBEDTLS_SCRIPT_ID := $(shell sha256sum tools/build-mbedtls.sh | cut -c1-16)
MBEDTLS_BUILD_ID := $(shell printf '%s\n' \
	'$(CC)|$(MBEDTLS_CC_ID)|$(AR)|$(MBEDTLS_AR_ID)|$(MBEDTLS_CFLAGS)|$(MBEDTLS_SCRIPT_ID)' \
	| sha256sum | cut -c1-16)
MBEDTLS_BUILD_DIR := $(MBEDTLS_DIR)/$(MBEDTLS_BUILD_ID)
MBEDTLS_SOURCE_DIR := $(MBEDTLS_BUILD_DIR)/source
MBEDTLS_MARKER := $(MBEDTLS_BUILD_DIR)/.ready

ifeq ($(PROFILE),minimal)
  CFLAGS_PROFILE := -DPROFILE_MINIMAL=1
  LIBS :=
  TLS_DEPS :=
  TLS_CHECK :=
else ifeq ($(PROFILE),encrypted)
  # MBEDTLS_MEMORY_BUFFER_ALLOC_C points mbedTLS at the boot arena, so the
  # zero-heap guarantee survives
  CFLAGS_PROFILE := -DPROFILE_ENCRYPTED=1 -I$(MBEDTLS_SOURCE_DIR)/include
  LIBS := -L$(MBEDTLS_SOURCE_DIR)/library -lmbedtls -lmbedx509 -lmbedcrypto
  TLS_DEPS := $(MBEDTLS_MARKER)
  TLS_CHECK := mbedtls
else
  $(error Unknown PROFILE '$(PROFILE)'. Use: minimal | encrypted)
endif

# Apache-2.0 4(a) and the MIT notice clause: a recipient of the binary gets the
# license text
LICENSE_FILES := $(BUILD)/THIRD_PARTY_LICENSES.md

# Off by default on purpose
# FEATURES += -DFEATURE_DGA_FILTER=1
# FEATURES += -DFEATURE_IO_URING=1     # opt-in only, pulls in liburing

CFLAGS  := $(CFLAGS_COMMON) $(CFLAGS_ARCH) $(CFLAGS_PROFILE) $(FEATURES)

# src/embedded.c is compiled through its own rule below, because a generated
# list replaces it
SRC := $(filter-out src/embedded.c,$(wildcard src/*.c))
OBJ := $(patsubst src/%.c,$(BUILD)/%.o,$(SRC)) $(BUILD)/embedded.o
DEP := $(patsubst src/%.c,$(BUILD)/%.d,$(SRC))

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

# A prerequisite list expands where it is written, so this has to precede every
# rule that names it. Commands built in one step get no depfiles and depend on
# every header instead: a stale binary reports PASS for code that is gone, and a
# stale generator writes a list in a format the daemon no longer reads
HDR := $(wildcard src/*.h)

.PHONY: all check clean tools test test-static test-static-run fuzz fuzz-quick mbedtls
all: $(TARGET)

$(TARGET): $(OBJ) $(TLS_DEPS) | $(LICENSE_FILES) $(TLS_CHECK)
	@test -n "$(strip $(SRC))" || { echo "No sources in src/ yet"; exit 1; }
	$(CC) $(CFLAGS) $(OBJ) -o $@ $(LIBS)
	$(call assert_static,$@)
	@echo "built $@"

$(BUILD)/THIRD_PARTY_LICENSES.md: THIRD_PARTY_LICENSES.md | $(BUILD)
	cp $< $@

mbedtls: $(MBEDTLS_MARKER)
	@if [ ! -f "$(MBEDTLS_SOURCE_DIR)/include/mbedtls/ssl.h" ] \
		|| [ ! -f "$(MBEDTLS_SOURCE_DIR)/library/libmbedtls.a" ] \
		|| [ ! -f "$(MBEDTLS_SOURCE_DIR)/library/libmbedx509.a" ] \
		|| [ ! -f "$(MBEDTLS_SOURCE_DIR)/library/libmbedcrypto.a" ]; then \
		CC="$(CC)" AR="$(AR)" MBEDTLS_CFLAGS="$(MBEDTLS_CFLAGS)" \
			sh tools/build-mbedtls.sh "$(MBEDTLS_BUILD_DIR)" \
			&& touch "$(MBEDTLS_MARKER)"; \
	fi

$(MBEDTLS_MARKER): tools/build-mbedtls.sh | $(BUILD)
	CC="$(CC)" AR="$(AR)" MBEDTLS_CFLAGS="$(MBEDTLS_CFLAGS)" \
		sh $< "$(MBEDTLS_BUILD_DIR)"
	@touch $@

# Compiles domain lists into the trie the daemon maps. Host tool, so it is not
# built with the shipped flags, and it links the stub rather than its own output
tools: $(BUILD)/mkblocklist
$(BUILD)/mkblocklist: tools/mkblocklist.c src/blocklist.c src/wire.c src/embedded.c $(HDR) | $(BUILD)
	$(HOSTCC) -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Isrc $(filter %.c,$^) -o $@

# One of the two definitions of G_EMBEDDED_TRIE reaches the link: the stub, or
# the array mkblocklist writes from EMBED_LIST
ifeq ($(strip $(EMBED_LIST)),)
  EMBED_SRC := src/embedded.c
else
  EMBED_SRC := $(BUILD)/embedded_gen.c

$(BUILD)/embedded_gen.c: $(EMBED_LIST) $(BUILD)/mkblocklist | $(BUILD)
	$(BUILD)/mkblocklist -c $@ $(EMBED_LIST)
endif

$(BUILD)/embedded.o: $(EMBED_SRC) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# Health probe binary run by a supervisor. Keep it tiny
check: $(BUILD)/dns_blocker.check
$(BUILD)/dns_blocker.check: tools/check.c | $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_ARCH) $< -o $@
	$(call assert_static,$@)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

ifeq ($(PROFILE),encrypted)
$(OBJ): $(TLS_DEPS) | $(TLS_CHECK)
endif

# Host tests. Sanitizers are incompatible with -static-pie, so these do not
# share CFLAGS with the shipped binary
TEST_CFLAGS := -std=c11 -O1 -g \
	-fsanitize=address,undefined -fno-omit-frame-pointer \
	-Wall -Wextra -Wpedantic -Wshadow -Wconversion \
	-Isrc

ifeq ($(PROFILE),encrypted)
  ENCRYPTED_TESTS := $(BUILD)/upstream_dot_test $(BUILD)/tls_backend_test $(BUILD)/fetch_tls_test
else
  ENCRYPTED_TESTS :=
endif

test: $(BUILD)/wire_test $(BUILD)/cache_test $(BUILD)/msg_test $(BUILD)/verify_test $(BUILD)/blocklist_test $(BUILD)/listline_test $(BUILD)/hosts_test $(BUILD)/upstream_test $(BUILD)/fetch_test $(BUILD)/server_test $(BUILD)/tls_test $(BUILD)/fuzz_quick $(ENCRYPTED_TESTS)
	@$(BUILD)/wire_test
	@$(BUILD)/cache_test
	@$(BUILD)/msg_test
	@$(BUILD)/verify_test
	@$(BUILD)/blocklist_test
	@$(BUILD)/listline_test
	@$(BUILD)/hosts_test
	@$(BUILD)/upstream_test
	@$(BUILD)/fetch_test
	@$(BUILD)/server_test
	@$(BUILD)/tls_test
	@$(BUILD)/fuzz_quick 50000
ifeq ($(PROFILE),encrypted)
	@$(BUILD)/upstream_dot_test
	@$(BUILD)/tls_backend_test
	@$(BUILD)/fetch_tls_test
endif

$(BUILD)/wire_test: tests/wire_test.c src/wire.c $(HDR) | $(BUILD)
	$(CC) $(TEST_CFLAGS) $(filter %.c,$^) -o $@

$(BUILD)/cache_test: tests/cache_test.c src/cache.c src/wire.c src/arena.c $(HDR) | $(BUILD)
	$(CC) $(TEST_CFLAGS) $(filter %.c,$^) -o $@

$(BUILD)/msg_test: tests/msg_test.c src/msg.c src/wire.c $(HDR) | $(BUILD)
	$(CC) $(TEST_CFLAGS) $(filter %.c,$^) -o $@

$(BUILD)/verify_test: tests/verify_test.c src/verify.c src/wire.c $(HDR) | $(BUILD)
	$(CC) $(TEST_CFLAGS) $(filter %.c,$^) -o $@

$(BUILD)/blocklist_test: tests/blocklist_test.c src/blocklist.c src/wire.c $(EMBED_SRC) $(HDR) | $(BUILD)
	$(CC) $(TEST_CFLAGS) $(filter %.c,$^) -o $@

# The generator's line parsing. Header-only, so the tool and the test read the
# same code rather than two copies of one format
$(BUILD)/listline_test: tests/listline_test.c tools/listline.h | $(BUILD)
	$(CC) $(TEST_CFLAGS) -Itools $< -o $@

$(BUILD)/hosts_test: tests/hosts_test.c src/hosts.c src/wire.c src/arena.c $(HDR) | $(BUILD)
	$(CC) $(TEST_CFLAGS) $(filter %.c,$^) -o $@

# Selection, ranking and health. No sockets, so the policy is tested apart from
# the transport that carries it
$(BUILD)/upstream_test: tests/upstream_test.c src/upstream.c src/msg.c src/verify.c src/wire.c $(HDR) | $(BUILD)
	$(CC) $(TEST_CFLAGS) $(filter %.c,$^) -o $@

# The release response parser. Attacker-controlled bytes, so it is tested apart
# from the socket that delivers them
$(BUILD)/fetch_test: tests/fetch_test.c src/fetch.c $(HDR) | $(BUILD)
	$(CC) $(TEST_CFLAGS) $(filter %.c,$^) -o $@

# Drives the transfer states against scripted bytes. Links without src/tls.c,
# so the test supplies the shim and no case needs a live peer
$(BUILD)/fetch_tls_test: tests/fetch_tls_test.c src/fetch.c $(HDR) $(TLS_DEPS) | $(BUILD) $(TLS_CHECK)
	$(CC) $(TEST_CFLAGS) -DPROFILE_ENCRYPTED=1 -I$(MBEDTLS_SOURCE_DIR)/include $(filter %.c,$^) -o $@ $(LIBS)

$(BUILD)/upstream_dot_test: tests/upstream_dot_test.c src/upstream.c src/msg.c src/verify.c src/wire.c $(HDR) $(TLS_DEPS) | $(BUILD) $(TLS_CHECK)
	$(CC) $(TEST_CFLAGS) -DPROFILE_ENCRYPTED=1 -I$(MBEDTLS_SOURCE_DIR)/include $(filter %.c,$^) -o $@

$(BUILD)/tls_backend_test: tests/tls_backend_test.c src/tls.c src/arena.c $(HDR) $(TLS_DEPS) | $(BUILD) $(TLS_CHECK)
	$(CC) $(TEST_CFLAGS) -DPROFILE_ENCRYPTED=1 -I$(MBEDTLS_SOURCE_DIR)/include $(filter %.c,$^) -o $@ $(LIBS)

# Binds loopback sockets and drives a real query through the whole path
$(BUILD)/server_test: tests/server_test.c src/server.c src/upstream.c src/msg.c src/cache.c src/verify.c src/blocklist.c src/hosts.c src/wire.c src/arena.c $(EMBED_SRC) $(HDR) | $(BUILD)
	$(CC) $(TEST_CFLAGS) -DCFG_UPSTREAM_TIMEOUT_MS=120 $(filter %.c,$^) -o $@ -lpthread

$(BUILD)/tls_test: tests/tls_test.c src/tls.c src/arena.c $(HDR) | $(BUILD)
	$(CC) $(TEST_CFLAGS) $(filter %.c,$^) -o $@

# Sanitizer-free copies of the pure tests, built with the shipped flags so they
# cross-compile and run under qemu-user on the target instruction set. This is
# the only way the byte-wise field reads get exercised on real ARM
XTEST := $(BUILD)/wire_test_native $(BUILD)/cache_test_native $(BUILD)/msg_test_native $(BUILD)/verify_test_native $(BUILD)/blocklist_test_native $(BUILD)/hosts_test_native $(BUILD)/fetch_test_native

ifeq ($(PROFILE),encrypted)
  XTEST += $(BUILD)/upstream_dot_test_native $(BUILD)/tls_backend_test_native
endif

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

$(BUILD)/blocklist_test_native: tests/blocklist_test.c src/blocklist.c src/wire.c $(EMBED_SRC) $(HDR) | $(BUILD)
	$(CC) $(CFLAGS) $(filter %.c,$^) -o $@

$(BUILD)/hosts_test_native: tests/hosts_test.c src/hosts.c src/wire.c src/arena.c $(HDR) | $(BUILD)
	$(CC) $(CFLAGS) $(filter %.c,$^) -o $@

$(BUILD)/fetch_test_native: tests/fetch_test.c src/fetch.c $(HDR) | $(BUILD)
	$(CC) $(CFLAGS) $(filter %.c,$^) -o $@

$(BUILD)/upstream_dot_test_native: tests/upstream_dot_test.c src/upstream.c src/msg.c src/verify.c src/wire.c $(HDR) $(TLS_DEPS) | $(BUILD) $(TLS_CHECK)
	$(CC) $(CFLAGS) $(filter %.c,$^) -o $@

$(BUILD)/tls_backend_test_native: tests/tls_backend_test.c src/tls.c src/arena.c $(HDR) $(TLS_DEPS) | $(BUILD) $(TLS_CHECK)
	$(CC) $(CFLAGS) $(filter %.c,$^) -o $@ $(LIBS)

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
