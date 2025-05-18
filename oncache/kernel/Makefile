BPF_TARGETS := ebpf_plugin
BPF_C = ${BPF_TARGETS:=.c}
BPF_OBJ = ${BPF_C:.c=.o}

PROJ_DIR := ../

LLC := llc
CLANG := clang

$(BPF_OBJ): %.o: %.c  Makefile $(EXTRA_DEPS)
	$(CLANG) -S \
	    -target bpf \
	    $(CFLAGS) \
		-I$(PROJ_DIR) \
	    -Wall \
		-Wno-int-to-pointer-cast \
	    -Werror \
	    -O3 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

all: $(BPF_OBJ)
clean:
	rm -f *.o *.ll
