package main

import "C"

import (
	"fmt"
	"log"
	"os"
	"os/signal"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {
	log.SetPrefix(fmt.Sprintf("[%d]: ", os.Getpid()))
	log.SetFlags(log.Ldate | log.Lmicroseconds)

	log.Println("load bpf file...")

	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		panic(err)
	}
	defer bpfModule.Close()
	if err := bpfModule.BPFLoadObject(); err != nil {
		panic(err)
	}
	prog, err := bpfModule.GetProgram("kprobe__do_sys_openat2")
	if err != nil {
		panic(err)
	}
	if _, err := prog.AttachKprobe("do_sys_openat2"); err != nil {
		panic(err)
	}

	log.Println("waiting exite...")
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, os.Kill)
	<-c
	log.Fatal("program interrupted")
}
