package main

import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

type eData struct {
	Pid      uint32
	Comm     [16]byte
	Filename [256]byte
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

func (c eData) fileName() string {
	return string(bytes.TrimRight(c.Filename[:], "\x00"))
}

func (c eData) commName() string {
	return string(bytes.TrimRight(c.Comm[:], "\x00"))
}

func getTracePid() int {
	if len(os.Args) >= 2 {
		tpid := os.Args[1]
		if tpid != "" {
			result, err := strconv.Atoi(tpid)
			if err == nil {
				return result
			}
		}
	}
	return 0
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
	prog, err := bpfModule.GetProgram("tracepoint_openat")
	if err != nil {
		panic(err)
	}

	if _, err := prog.AttachTracepoint("syscalls", "sys_enter_openat"); err != nil {
		panic(err)
	}

	pidMap, err := bpfModule.GetMap("pid_filter")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	currPid := uint32(1)
	value1 := uint32(getTracePid())
	key1Unsafe := unsafe.Pointer(&currPid)
	value1Unsafe := unsafe.Pointer(&value1)
	pidMap.Update(key1Unsafe, value1Unsafe)

	eventsChannel := make(chan []byte)
	pb, err := bpfModule.InitRingBuf("events", eventsChannel)
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
			var ed eData
			var dataBuffer *bytes.Buffer
			dataBuffer = bytes.NewBuffer(e)
			err = binary.Read(dataBuffer, binary.LittleEndian, &ed)
			if err != nil {
				log.Println(err)
				continue
			}
			log.Printf("pid[%d] comm[%s] opened %s ", ed.Pid, ed.commName(), ed.fileName())
		case <-c:
			log.Fatal("program interrupted")
			break
		}
	}
}
