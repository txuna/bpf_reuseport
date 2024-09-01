//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf reuseport.c -- -I../headers

package main

import (
	"context"
	"log"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/cilium/ebpf/rlimit"
)

const (
	MAIN = 1
	SUB  = 2
)

func runServer(key uint32, option string, objs *bpfObjects) {

	lc := getListenConfig(objs.SelectSocket, option)
	ln, err := lc.Listen(context.Background(), "tcp", ":9988")
	if err != nil {
		log.Fatalf("[%s] %s", option, err)
	}

	fd := uint64(GetFdFromListener(ln))
	err = objs.SocketMap.Put(uint32(key), fd)
	if err != nil {
		log.Printf("[%s] %s\n", option, err)
		return
	}

	log.Printf("[%s] start echo server", option)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[%s] %s\n", option, err)
		}

		go func(conn net.Conn, option string) {
			_, err = conn.Write([]byte(option))
			if err != nil {
				return
			}

			conn.Close()
		}(conn, option)
	}
}

func main() {

	runtime.GOMAXPROCS(8)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}

	defer objs.Close()

	wg := &sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		runServer(MAIN, "main", &objs)
	}()

	time.Sleep(3 * time.Second)

	go func() {
		defer wg.Done()
		runServer(SUB, "sub", &objs)
	}()

	wg.Wait()
}
