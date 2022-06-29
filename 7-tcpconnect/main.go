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

type cdata struct {
	SourceIP   uint32
	DstIP      uint32
	SourcePort uint32
	DstPort    uint32
	Family     uint32
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
	prog, err := bpfModule.GetProgram("kb_tcp_connect")
	if err != nil {
		panic(err)
	}
	if _, err := prog.AttachKprobe("tcp_connect"); err != nil {
		panic(err)
	}

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
			var cd cdata
			var dataBuffer *bytes.Buffer

			dataBuffer = bytes.NewBuffer(e)
			err = binary.Read(dataBuffer, binary.LittleEndian, &cd)
			if err != nil {
				log.Println(err)
				continue
			}
			log.Printf("SourceIP: [%d] DstIP: [%d] -- Family: %d \n", cd.SourceIP, cd.DstIP, cd.Family)
		case <-c:
			log.Fatal("program interrupted")
			break
		}
	}
}
