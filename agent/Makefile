# -----------------------------
# Compiler & Linker
# -----------------------------
GCC      ?= gcc
MODE     ?= release
SANITIZE ?= 0

IS_CLANG := $(shell $(GCC) -dM -E - < /dev/null 2>/dev/null | grep -c __clang__)
STACK_CLASH_CFLAG := $(shell printf '' | $(GCC) -x c -c -o /dev/null -fstack-clash-protection - >/dev/null 2>&1 && printf '%s' -fstack-clash-protection)

# -----------------------------
# CFLAGS
# -----------------------------
CFLAGS  ?= -std=gnu2x -fdata-sections -ffunction-sections \
		-Wall -Wextra -Werror -pedantic\
		-Wshadow -Wpointer-arith -Wcast-align -Wstrict-prototypes \
		-Wmissing-prototypes -Wmissing-declarations -Wmissing-field-initializers \
		-Wredundant-decls -Wformat=2 \
		-Wstack-protector \
		-Wundef -Wwrite-strings -Wdouble-promotion \
		-Wsign-conversion -Wconversion \
		-fstack-protector-strong $(STACK_CLASH_CFLAG) -fno-common -fPIE \
		-D_DEFAULT_SOURCE \
		-MMD -MP

ifeq ($(IS_CLANG),0)
CFLAGS += -Wformat-truncation=2 -Wformat-overflow=2 \
		-Wstringop-overflow=2 -Wstringop-truncation \
		-Wduplicated-cond -Wduplicated-branches -Wlogical-op \
		-Wjump-misses-init
else
CFLAGS += -Wno-gnu-zero-variadic-macro-arguments
endif

# LDFLAGS
LDFLAGS ?= -static-pie -Wl,--gc-sections -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wl,--build-id

# Release / Debug
ifeq ($(MODE),debug)
	CFLAGS += -g -O0 -DDEBUG
	# remove static link for debug
	LDFLAGS := $(filter-out -static -static-pie,$(LDFLAGS))
else
	CFLAGS += -Os -g -flto -D_FORTIFY_SOURCE=2
	LDFLAGS += -flto
endif

ifeq ($(SANITIZE),1)
	CFLAGS += -fsanitize=address -fsanitize=undefined
	LDFLAGS += -fsanitize=address -fsanitize=undefined
	LDFLAGS := $(filter-out -static -static-pie,$(LDFLAGS))
endif

ifneq ($(filter -static -static-pie,$(LDFLAGS)),)
	CFLAGS += -DTF_STATIC_BUILD=1
endif

LIBS    = 

# -----------------------------
# Directories
# -----------------------------
SRC_DIR     = src
INCLUDE_DIR = include
BUILD_DIR   = build
BIN_DIR     = bin

# -----------------------------
# Source / Object / Dependency
# -----------------------------
SRCS := $(shell find $(SRC_DIR) -name '*.c')
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))
DEPS := $(OBJS:.o=.d)
INCLUDES = -I$(INCLUDE_DIR)

TARGET = $(BIN_DIR)/tracefox-agent

# -----------------------------
# Build Rules
# -----------------------------
all: $(TARGET)

$(TARGET): $(OBJS) | $(BIN_DIR)
	@echo "Linking $@..."
	$(GCC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS) $(LIBS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	@echo "Compiling $<..."
	@mkdir -p $(dir $@)
	$(GCC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BUILD_DIR):
	@mkdir -p $@

$(BIN_DIR):
	@mkdir -p $@

compdb:
	@echo "Generating compile_commands.json..."
	@$(MAKE) clean
	@bear -- $(MAKE) all

-include $(DEPS)
# -----------------------------
# Utilities
# -----------------------------
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR) $(BIN_DIR)

sanitize:
	@$(MAKE) clean
	@$(MAKE) SANITIZE=1 MODE=debug

debug:
	@$(MAKE) clean
	@$(MAKE) all MODE=debug

# Release
release:
	@echo ">>> Building Release Version..."
	@$(MAKE) clean
	@$(MAKE) all MODE=release
	@echo ">>> Packaging..."
	@echo "  Extracting debug symbols..."
	@objcopy --only-keep-debug $(TARGET) $(TARGET).debug
	@echo "  Stripping binary..."
	@strip --strip-unneeded $(TARGET)
	@echo "  Adding debug link..."
	@objcopy --add-gnu-debuglink=$(TARGET).debug $(TARGET)
	@echo ">>> Release Build Complete!"
	@ls -lh $(TARGET) $(TARGET).debug
	@echo ">>> Security Analysis:"
	@checksec --file=$(TARGET)
	@echo ">>> Security Analysis (from debug symbols):"
	@checksec --file=$(TARGET).debug

checksec: $(TARGET)
	@if command -v checksec >/dev/null 2>&1; then \
		echo "Running checksec on $(TARGET)..."; \
		checksec --file=$(TARGET); \
	else \
		echo "checksec not found, skipping security check"; \
	fi

print-%:
	@echo $* = $($*)

.PHONY: all clean sanitize release checksec
