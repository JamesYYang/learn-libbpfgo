all: vmlinux.h bpf_target go_target

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

bpf_target: main.bpf.c
	clang -g -O2 -Wall -c -target bpf -D__TARGET_ARCH_x86 -o main.bpf.o main.bpf.c

go_target: main.bpf.o main.go
	CC=clang CGO_CFLAGS="-I /usr/include/bpf" CGO_LDFLAGS="/root/libbpf/src/root/usr/lib64/libbpf.a" go build -o hello-world

clean:
	rm -f main.bpf.o hello-world