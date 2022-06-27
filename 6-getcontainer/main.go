package main

import "C"

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"regexp"

	bpf "github.com/aquasecurity/libbpfgo"
)

type cdata struct {
	HostPid  uint32
	HostPpid uint32
	HostName [65]byte
	Comm     [100]byte
}

func (c cdata) hostName() string {
	return string(bytes.TrimRight(c.HostName[:], "\x00"))
}

func (c cdata) commName() string {
	return string(bytes.TrimRight(c.Comm[:], "\x00"))
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
	prog, err := bpfModule.GetProgram("tracepoint_execve")
	if err != nil {
		panic(err)
	}
	if _, err := prog.AttachTracepoint("syscalls", "sys_enter_execve"); err != nil {
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
			cid := getContainerId(cd.HostPpid)
			if cid != "" {
				log.Printf("ContainerID: [%s] HostName: [%s] -- Comm: %s \n", cid, cd.hostName(), cd.commName())
			}

		case <-c:
			log.Fatal("program interrupted")
			break
		}
	}
}

var reContainerId = regexp.MustCompile(`docker-([0-9a-f]{64}).scope`)

func getContainerId(pid uint32) string {
	if pid == 0 {
		return ""
	}
	path := fmt.Sprintf("/proc/%d/cgroup", pid)
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		log.Printf("open file %s failed: %+v", path, err)
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		matches := reContainerId.FindAllStringSubmatch(line, 1)
		if len(matches) > 0 {
			return matches[0][1]
		}
	}
	return ""
}
