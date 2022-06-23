package main

import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"

	bpf "github.com/aquasecurity/libbpfgo"
)

type eData struct {
	Pid  uint32
	Comm string
}

func resizeMap(module *bpf.Module, name string, size uint32) error {
	m, err := module.GetMap(name)
	if err != nil {
		return err
	}
	if err = m.Resize(size); err != nil {
		return err
	}
	if actual := m.GetMaxEntries(); actual != size {
		return fmt.Errorf("map resize failed, expected %v, actual %v", size, actual)
	}
	return nil
}

func main() {
	log.SetPrefix(fmt.Sprintf("[%d]: ", os.Getpid()))
	log.SetFlags(log.Ldate | log.Lmicroseconds)

	log.Println("load bpf file...")

	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		panic(err)
	}
	defer bpfModule.Close()

	if err = resizeMap(bpfModule, "events", 8192); err != nil {
		panic(err)
	}

	if err := bpfModule.BPFLoadObject(); err != nil {
		panic(err)
	}
	prog, err := bpfModule.GetProgram("kprobe__sys_execve")
	if err != nil {
		panic(err)
	}
	if _, err := prog.AttachKprobe("__x64_sys_execve"); err != nil {
		panic(err)
	}

	eventsChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	pb, err := bpfModule.InitPerfBuf("events", eventsChannel, lostChannel, 1)
	if err != nil {
		panic(err)
	}

	pb.Start()
	defer func() {
		pb.Stop()
		pb.Close()
	}()

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, os.Kill)

	for {
		select {
		case e := <-eventsChannel:
			pid := binary.LittleEndian.Uint32(e[0:4])
			comm := string(bytes.TrimRight(e[4:], "\x00")) // Remove excess 0's from comm, treat as string
			ed := eData{
				Pid:  pid,
				Comm: comm,
			}
			log.Printf("pid[%d] %v", ed.Pid, ed.Comm)
		case e := <-lostChannel:
			log.Printf("lost %d events", e)
		case <-c:
			log.Fatal("program interrupted")
			break
		}
	}
}
