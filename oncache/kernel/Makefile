BPF_TARGETS := ebpf_plugin
BPF_C = ${BPF_TARGETS:=.c}
BPF_OBJ = ${BPF_C:.c=.o}

LIBBPF_DIR ?= ../libbpf

LLC := llc
CLANG := clang

$(BPF_OBJ): %.o: %.c  Makefile
	$(CLANG) -S \
	    -target bpf \
	    -Wall \
	    -Wno-int-to-pointer-cast \
	    -Werror \
	    -I$(LIBBPF_DIR)/include/uapi/ \
	    -O3 -emit-llvm -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

all: $(BPF_OBJ)
clean:
	rm -f *.o *.ll
