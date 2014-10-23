// Package fastping is an ICMP ping library inspired by AnyEvent::FastPing Perl
// module to send ICMP ECHO REQUEST packets quickly. Original Perl module is
// available at
// http://search.cpan.org/~mlehmann/AnyEvent-FastPing-2.01/
//
// It hasn't been fully implemented original functions yet.
//
// Here is an example:
//
//	p := fastping.NewPinger()
//	ra, err := net.ResolveIPAddr("ip4:icmp", os.Args[1])
//	if err != nil {
//		fmt.Println(err)
//		os.Exit(1)
//	}
//	p.AddIPAddr(ra)
//	p.OnRecv = func(addr *net.IPAddr, rtt time.Duration) {
//		fmt.Printf("IP Addr: %s receive, RTT: %v\n", addr.String(), rtt)
//	}
//	p.OnIdle = func() {
//		fmt.Println("finish")
//	}
//	err = p.Run()
//	if err != nil {
//		fmt.Println(err)
//	}
//
// It sends an ICMP packet and wait a response. If it receives a response,
// it calls "receive" callback. After that, MaxRTT time passed, it calls
// "idle" callback. If you need more example, please see "cmd/ping/ping.go".
//
// This library needs to run as a superuser for sending ICMP packets so when
// you run go test, please run as a following
//
//	sudo go test
//
package fastping

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"syscall"
	"time"
)

func timeToBytes(t time.Time) []byte {
	nsec := t.UnixNano()
	b := make([]byte, 8)
	for i := uint8(0); i < 8; i++ {
		b[i] = byte((nsec >> ((7 - i) * 8)) & 0xff)
	}
	return b
}

func bytesToTime(b []byte) time.Time {
	var nsec int64
	for i := uint8(0); i < 8; i++ {
		nsec += int64(b[i]) << ((7 - i) * 8)
	}
	return time.Unix(nsec/1000000000, nsec%1000000000)
}

func isIPv4(ip net.IP) bool {
	return len(ip.To4()) == net.IPv4len
}

func isIPv6(ip net.IP) bool {
	return len(ip) == net.IPv6len
}

type packet struct {
	bytes []byte
	addr  *net.IPAddr
}

type context struct {
	stop chan bool
	done chan bool
	err  error
}

func newContext() *context {
	return &context{
		stop: make(chan bool),
		done: make(chan bool),
	}
}

// Pinger represents ICMP packet sender/receiver
type Pinger struct {
	id  int
	seq int
	// key string is IPAddr.String()
	addrs   map[string]*net.IPAddr
	hasIPv4 bool
	hasIPv6 bool
	ctx     *context
	mu      sync.Mutex
	// Number of (nano,milli)seconds of an idle timeout. Once it passed,
	// the library calls an idle callback function. It is also used for an
	// interval time of RunLoop() method
	MaxRTT time.Duration
	// OnRecv is called with a response packet's source address and its
	// elapsed time when Pinger receives a response packet.
	OnRecv func(*net.IPAddr, time.Duration)
	// OnIdle is called when MaxRTT time passed
	OnIdle func()
	// If Debug is true, it prints debug messages to stdout.
	Debug bool
}

// NewPinger returns a new Pinger struct pointer
func NewPinger() *Pinger {
	rand.Seed(time.Now().UnixNano())
	return &Pinger{
		id:      rand.Intn(0xffff),
		seq:     rand.Intn(0xffff),
		addrs:   make(map[string]*net.IPAddr),
		hasIPv4: false,
		hasIPv6: false,
		MaxRTT:  time.Second,
		OnRecv:  nil,
		OnIdle:  nil,
		Debug:   false,
	}
}

// AddIP adds an IP address to Pinger. ipaddr arg should be a string like
// "192.0.2.1".
func (p *Pinger) AddIP(ipaddr string) error {
	addr := net.ParseIP(ipaddr)
	if addr == nil {
		return fmt.Errorf("%s is not a valid textual representation of an IP address", ipaddr)
	}
	p.mu.Lock()
	p.addrs[addr.String()] = &net.IPAddr{IP: addr}
	if isIPv4(addr) {
		p.hasIPv4 = true
	} else if isIPv6(addr) {
		p.hasIPv6 = true
	}
	p.mu.Unlock()
	return nil
}

// AddIPAddr adds an IP address to Pinger. ip arg should be a net.IPAddr
// pointer.
func (p *Pinger) AddIPAddr(ip *net.IPAddr) {
	p.mu.Lock()
	p.addrs[ip.String()] = ip
	if isIPv4(ip.IP) {
		p.hasIPv4 = true
	} else if isIPv6(ip.IP) {
		p.hasIPv6 = true
	}
	p.mu.Unlock()
}

// AddHandler adds event handler to Pinger. event arg should be "receive" or
// "idle" string.
//
// **CAUTION** This function is deprecated. Please use OnRecv and OnIdle field
// of Pinger struct to set following handlers.
//
// "receive" handler should be
//
//	func(addr *net.IPAddr, rtt time.Duration)
//
// type function. The handler is called with a response packet's source address
// and its elapsed time when Pinger receives a response packet.
//
// "idle" handler should be
//
//	func()
//
// type function. The handler is called when MaxRTT time passed. For more
// detail, please see Run() and RunLoop().
func (p *Pinger) AddHandler(event string, handler interface{}) error {
	switch event {
	case "receive":
		if hdl, ok := handler.(func(*net.IPAddr, time.Duration)); ok {
			p.mu.Lock()
			p.OnRecv = hdl
			p.mu.Unlock()
			return nil
		}
		return errors.New("receive event handler should be `func(*net.IPAddr, time.Duration)`")
	case "idle":
		if hdl, ok := handler.(func()); ok {
			p.mu.Lock()
			p.OnIdle = hdl
			p.mu.Unlock()
			return nil
		}
		return errors.New("idle event handler should be `func()`")
	}
	return errors.New("No such event: " + event)
}

// Run invokes a single send/receive procedure. It sends packets to all hosts
// which have already been added by AddIP() etc. and wait those responses. When
// it receives a response, it calls "receive" handler registered by AddHander().
// After MaxRTT seconds, it calls "idle" handler and returns to caller with
// an error value. It means it blocks until MaxRTT seconds passed. For the
// purpose of sending/receiving packets over and over, use RunLoop().
func (p *Pinger) Run() error {
	p.mu.Lock()
	p.ctx = newContext()
	p.mu.Unlock()
	p.run(true)
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ctx.err
}

// RunLoop invokes send/receive procedure repeatedly. It sends packets to all
// hosts which have already been added by AddIP() etc. and wait those responses.
// When it receives a response, it calls "receive" handler registered by
// AddHander(). After MaxRTT seconds, it calls "idle" handler, resend packets
// and wait those response. MaxRTT works as an interval time.
//
// This is a non-blocking method so immediately returns. If you want to monitor
// and stop sending packets, use Done() and Stop() methods. For example,
//
//	p.RunLoop()
//	ticker := time.NewTicker(time.Millisecond * 250)
//	select {
//	case <-p.Done():
//		if err := p.Err(); err != nil {
//			log.Fatalf("Ping failed: %v", err)
//		}
//	case <-ticker.C:
//		break
//	}
//	ticker.Stop()
//	p.Stop()
//
// For more details, please see "cmd/ping/ping.go".
func (p *Pinger) RunLoop() {
	p.mu.Lock()
	p.ctx = newContext()
	p.mu.Unlock()
	go p.run(false)
}

// Done returns a channel that is closed when RunLoop() is stopped by an error
// or Stop(). It must be called after RunLoop() call. If not, it causes panic.
func (p *Pinger) Done() <-chan bool {
	return p.ctx.done
}

// Stop stops RunLoop(). It must be called after RunLoop(). If not, it causes
// panic.
func (p *Pinger) Stop() {
	p.debugln("Stop(): close(p.ctx.stop)")
	close(p.ctx.stop)
	p.debugln("Stop(): <-p.ctx.done")
	<-p.ctx.done
}

// Err returns an error that is set by RunLoop(). It must be called after
// RunLoop(). If not, it causes panic.
func (p *Pinger) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ctx.err
}

func (p *Pinger) listen(netProto string) *net.IPConn {
	conn, err := net.ListenIP(netProto, nil)
	if err != nil {
		p.mu.Lock()
		p.ctx.err = err
		p.mu.Unlock()
		p.debugln("Run(): close(p.ctx.done)")
		close(p.ctx.done)
		return nil
	}
	return conn
}

func (p *Pinger) run(once bool) {
	p.debugln("Run(): Start")
	var conn, conn6 *net.IPConn
	if p.hasIPv4 {
		if conn = p.listen("ip4:icmp"); conn == nil {
			return
		}
		defer conn.Close()
	}

	if p.hasIPv6 {
		if conn6 = p.listen("ip6:ipv6-icmp"); conn6 == nil {
			return
		}
		defer conn6.Close()
	}

	recv := make(chan *packet)
	recvCtx := newContext()
	wg := new(sync.WaitGroup)

	p.debugln("Run(): call recvICMP()")
	if conn != nil {
		wg.Add(1)
		go p.recvICMP(conn, recv, recvCtx, wg)
	}
	if conn6 != nil {
		wg.Add(1)
		go p.recvICMP(conn6, recv, recvCtx, wg)
	}

	p.debugln("Run(): call sendICMP()")
	queue, err := p.sendICMP(conn, conn6)

	ticker := time.NewTicker(p.MaxRTT)

mainloop:
	for {
		select {
		case <-p.ctx.stop:
			p.debugln("Run(): <-p.ctx.stop")
			break mainloop
		case <-recvCtx.done:
			p.debugln("Run(): <-recvCtx.done")
			p.mu.Lock()
			err = recvCtx.err
			p.mu.Unlock()
			break mainloop
		case <-ticker.C:
			p.mu.Lock()
			handler := p.OnIdle
			p.mu.Unlock()
			if handler != nil {
				handler()
			}
			if once || err != nil {
				break mainloop
			}
			p.debugln("Run(): call sendICMP()")
			queue, err = p.sendICMP(conn, conn6)
		case r := <-recv:
			p.debugln("Run(): <-recv")
			p.procRecv(r, queue)
		}
	}

	ticker.Stop()

	p.debugln("Run(): close(recvCtx.stop)")
	close(recvCtx.stop)
	p.debugln("Run(): wait recvICMP()")
	wg.Wait()

	p.mu.Lock()
	p.ctx.err = err
	p.mu.Unlock()

	p.debugln("Run(): close(p.ctx.done)")
	close(p.ctx.done)
	p.debugln("Run(): End")
}

func (p *Pinger) sendICMP(conn, conn6 *net.IPConn) (map[string]*net.IPAddr, error) {
	p.debugln("sendICMP(): Start")
	p.mu.Lock()
	p.id = rand.Intn(0xffff)
	p.seq = rand.Intn(0xffff)
	p.mu.Unlock()
	queue := make(map[string]*net.IPAddr)
	wg := new(sync.WaitGroup)
	for key, addr := range p.addrs {
		var typ int
		var cn *net.IPConn
		if isIPv4(addr.IP) {
			typ = icmpv4EchoRequest
			cn = conn
		} else if isIPv6(addr.IP) {
			typ = icmpv6EchoRequest
			cn = conn6
		} else {
			continue
		}
		if cn == nil {
			continue
		}

		p.mu.Lock()
		bytes, err := (&icmpMessage{
			Type: typ, Code: 0,
			Body: &icmpEcho{
				ID: p.id, Seq: p.seq,
				Data: timeToBytes(time.Now()),
			},
		}).Marshal()
		p.mu.Unlock()
		if err != nil {
			wg.Wait()
			return queue, err
		}

		queue[key] = addr

		p.debugln("sendICMP(): Invoke goroutine")
		wg.Add(1)
		go func(conn *net.IPConn, ra *net.IPAddr, b []byte) {
			for {
				if _, _, err := conn.WriteMsgIP(bytes, nil, ra); err != nil {
					if neterr, ok := err.(*net.OpError); ok {
						if neterr.Err == syscall.ENOBUFS {
							continue
						}
					}
				}
				break
			}
			p.debugln("sendICMP(): WriteMsgIP End")
			wg.Done()
		}(cn, addr, bytes)
	}
	wg.Wait()
	p.debugln("sendICMP(): End")
	return queue, nil
}

func (p *Pinger) recvICMP(conn *net.IPConn, recv chan<- *packet, ctx *context, wg *sync.WaitGroup) {
	p.debugln("recvICMP(): Start")
	for {
		select {
		case <-ctx.stop:
			p.debugln("recvICMP(): <-ctx.stop")
			wg.Done()
			p.debugln("recvICMP(): wg.Done()")
			return
		default:
		}

		bytes := make([]byte, 512)
		conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
		p.debugln("recvICMP(): ReadMsgIP Start")
		_, _, _, ra, err := conn.ReadMsgIP(bytes, nil)
		p.debugln("recvICMP(): ReadMsgIP End")
		if err != nil {
			if neterr, ok := err.(*net.OpError); ok {
				if neterr.Timeout() {
					p.debugln("recvICMP(): Read Timeout")
					continue
				} else {
					p.debugln("recvICMP(): OpError happen", err)
					p.mu.Lock()
					ctx.err = err
					p.mu.Unlock()
					p.debugln("recvICMP(): close(ctx.done)")
					close(ctx.done)
					p.debugln("recvICMP(): wg.Done()")
					wg.Done()
					return
				}
			}
		}
		p.debugln("recvICMP(): p.recv <- packet")

		select {
		case recv <- &packet{bytes: bytes, addr: ra}:
		case <-ctx.stop:
			p.debugln("recvICMP(): <-ctx.stop")
			wg.Done()
			p.debugln("recvICMP(): wg.Done()")
			return
		}
	}
}

func (p *Pinger) procRecv(recv *packet, queue map[string]*net.IPAddr) {
	addr := recv.addr.String()
	p.mu.Lock()
	if _, ok := p.addrs[addr]; !ok {
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()

	var bytes []byte
	if isIPv4(recv.addr.IP) {
		bytes = ipv4Payload(recv.bytes)
	} else if isIPv6(recv.addr.IP) {
		bytes = recv.bytes
	} else {
		return
	}

	var m *icmpMessage
	var err error
	if m, err = parseICMPMessage(bytes); err != nil {
		return
	}

	if m.Type != icmpv4EchoReply && m.Type != icmpv6EchoReply {
		return
	}

	var rtt time.Duration
	switch pkt := m.Body.(type) {
	case *icmpEcho:
		p.mu.Lock()
		if pkt.ID == p.id && pkt.Seq == p.seq {
			rtt = time.Since(bytesToTime(pkt.Data))
		}
		p.mu.Unlock()
	default:
		return
	}

	if _, ok := queue[addr]; ok {
		delete(queue, addr)
		p.mu.Lock()
		handler := p.OnRecv
		p.mu.Unlock()
		if handler != nil {
			handler(recv.addr, rtt)
		}
	}
}

func (p *Pinger) debugln(args ...interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Debug {
		log.Println(args...)
	}
}

func (p *Pinger) debugf(format string, args ...interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Debug {
		log.Printf(format, args...)
	}
}
