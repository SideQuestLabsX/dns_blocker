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
	-static-pie \
	-fstack-protector-strong \
	-fno-unwind-tables -fno-asynchronous-unwind-tables \
	-Wall -Wextra -Wpedantic -Wshadow -Wconversion \
	-Isrc

# ARMv6 (Pi Zero W / ARM1176): no movw/movt, no NEON, unaligned access unsafe.
# Read multi-byte DNS fields byte-wise regardless of target.
ifeq ($(ARCH),x86_64)
  CFLAGS_ARCH := -m64
else ifeq ($(ARCH),aarch64)
  CFLAGS_ARCH := -march=armv8-a
else ifeq ($(ARCH),armv7)
  CFLAGS_ARCH := -march=armv7-a -mfloat-abi=hard -mfpu=vfpv3-d16
else ifeq ($(ARCH),armv6)
  CFLAGS_ARCH := -march=armv6 -mfloat-abi=hard -mfpu=vfp
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

# make sets CC to cc by default, so a plain patsubst on %gcc leaves the compiler
# name here and the check below silently does nothing
READELF ?= $(if $(filter %gcc,$(CC)),$(patsubst %gcc,%readelf,$(CC)),readelf)

# Some toolchains accept -static-pie and still produce a dynamic binary. The
# compiler reports no error, and the result needs a loader on the target.
# Examine the linked output
define assert_static
	@if ! $(READELF) --version >/dev/null 2>&1; then \
		echo "$(READELF) not found, cannot verify that $(1) is static"; \
		rm -f $(1); \
		exit 1; \
	fi
	@if $(READELF) -l $(1) | grep -q INTERP; then \
		echo "$(1): dynamically linked. $(CC) did not honour -static-pie"; \
		rm -f $(1); \
		exit 1; \
	fi
endef

.PHONY: all check clean
all: $(TARGET)

$(TARGET): $(OBJ)
	@test -n "$(strip $(SRC))" || { echo "No sources in src/ yet"; exit 1; }
	$(CC) $(CFLAGS) $(OBJ) -o $@ $(LIBS)
	$(call assert_static,$@)
	@echo "built $@"

# Health probe binary run by a supervisor. Keep it tiny
check: $(BUILD)/dns_blocker.check
$(BUILD)/dns_blocker.check: tools/check.c | $(BUILD)
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_ARCH) $< -o $@
	$(call assert_static,$@)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

$(BUILD):
	@mkdir -p $(BUILD)

clean:
	@rm -rf build

-include $(DEP)
