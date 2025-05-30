KERNEL_DIR ?= ./kernel
USER_DIR ?= ./user

kernel:
	cd $(KERNEL_DIR) && $(MAKE)

user:
	cd $(USER_DIR) && go build

.PHONY: all clean kernel user
all: kernel user
