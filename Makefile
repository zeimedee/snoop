compile:
	clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 -I. -c bpf/snoop.c -o bpf/snoop.o