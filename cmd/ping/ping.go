package main

import (
	"fmt"
	"github.com/tatsushid/go-fastping"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type response struct {
	addr *net.IPAddr
	rtt  time.Duration
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s {hostname}\n", os.Args[0])
		os.Exit(1)
	}
	p := fastping.NewPinger()
	ra, err := net.ResolveIPAddr("ip4:icmp", os.Args[1])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	results := make(map[string]*response)
	results[ra.String()] = nil
	p.AddIPAddr(ra)

	onRecv, onIdle := make(chan *response), make(chan bool)
	p.AddHandler("receive", func(addr *net.IPAddr, t time.Duration) {
		onRecv <- &response{addr: addr, rtt: t}
	})
	p.AddHandler("idle", func() {
		onIdle <- true
	})

	p.MaxRTT = time.Second
	p.RunLoop()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)

loop:
	for {
		select {
		case <-c:
			fmt.Println("get interrupted")
			break loop
		case res := <-onRecv:
			if _, ok := results[res.addr.String()]; ok {
				results[res.addr.String()] = res
			}
		case <-onIdle:
			for host, r := range results {
				if r == nil {
					fmt.Printf("%s : unreachable %v\n", host, time.Now())
				} else {
					fmt.Printf("%s : %v %v\n", host, r.rtt, time.Now())
				}
				results[host] = nil
			}
		case <-p.Done():
			if err = p.Err(); err != nil {
				fmt.Println("Ping failed:", err)
			}
			break loop
		}
	}
	signal.Stop(c)
	p.Stop()
}
