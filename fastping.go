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
// This library needs to run as a superuser for sending ICMP packets when
// privileged raw ICMP endpoints is used so in such a case, to run go test
// for the package, please run like a following
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
	"runtime"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	TimeSliceLength  = 8
	ProtocolICMP     = 1
	ProtocolIPv6ICMP = 58
)

var (
	ipv4Proto = map[string]string{"ip": "ip4:icmp", "udp": "udp4"}
	ipv6Proto = map[string]string{"ip": "ip6:ipv6-icmp", "udp": "udp6"}
)

func byteSliceOfSize(n int) []byte {
	b := make([]byte, n)
	for i := 0; i < len(b); i++ {
		b[i] = 1
	}

	return b
}

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

func ipv4Payload(b []byte) []byte {
	if len(b) < ipv4.HeaderLen {
		return b
	}
	hdrlen := int(b[0]&0x0f) << 2
	return b[hdrlen:]
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
	sent    map[string]*net.IPAddr
	network string
	source  string
	source6 string
	hasIPv4 bool
	hasIPv6 bool
	ctx     *context
	mu      sync.Mutex

	// Size in bytes of the payload to send
	Size int
	// Number of (nano,milli)seconds of an idle timeout. Once it passed,
	// the library calls an idle callback function. It is also used for an
	// interval time of RunLoop() method
	MaxRTT time.Duration
	// OnRecv is called with a response packet's source address and its
	// elapsed time when Pinger receives a response packet.
	OnRecv func(*net.IPAddr, time.Duration)
	// OnIdle is called when MaxRTT time passed
	OnIdle func()
	// NumGoroutines defines how many goroutines are used when sending ICMP
	// packets and receiving IPv4/IPv6 ICMP responses. Its default is
	// runtime.NumCPU().
	NumGoroutines int
	// If Debug is true, it prints debug messages to stdout.
	Debug bool
}

// NewPinger returns a new Pinger struct pointer
func NewPinger() *Pinger {
	rand.Seed(time.Now().UnixNano())
	return &Pinger{
		id:            rand.Intn(0xffff),
		seq:           rand.Intn(0xffff),
		addrs:         make(map[string]*net.IPAddr),
		network:       "ip",
		source:        "",
		source6:       "",
		hasIPv4:       false,
		hasIPv6:       false,
		Size:          TimeSliceLength,
		MaxRTT:        time.Second,
		OnRecv:        nil,
		OnIdle:        nil,
		NumGoroutines: runtime.NumCPU(),
		Debug:         false,
	}
}

// Network sets a network endpoints for ICMP ping and returns the previous
// setting. network arg should be "ip" or "udp" string or if others are
// specified, it returns an error. If this function isn't called, Pinger
// uses "ip" as default.
func (p *Pinger) Network(network string) (string, error) {
	origNet := p.network
	switch network {
	case "ip":
		fallthrough
	case "udp":
		p.network = network
	default:
		return origNet, errors.New(network + " can't be used as ICMP endpoint")
	}
	return origNet, nil
}

// Source sets ipv4/ipv6 source IP for sending ICMP packets and returns the previous
// setting. Empty value indicates to use system default one (for both ipv4 and ipv6).
func (p *Pinger) Source(source string) (string, error) {
	// using ipv4 previous value for new empty one
	origSource := p.source
	if "" == source {
		p.mu.Lock()
		p.source = ""
		p.source6 = ""
		p.mu.Unlock()
		return origSource, nil
	}

	addr := net.ParseIP(source)
	if addr == nil {
		return origSource, errors.New(source + " is not a valid textual representation of an IPv4/IPv6 address")
	}

	if isIPv4(addr) {
		p.mu.Lock()
		p.source = source
		p.mu.Unlock()
	} else if isIPv6(addr) {
		origSource = p.source6
		p.mu.Lock()
		p.source6 = source
		p.mu.Unlock()
	} else {
		return origSource, errors.New(source + " is not a valid textual representation of an IPv4/IPv6 address")
	}

	return origSource, nil
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

// RemoveIP removes an IP address from Pinger. ipaddr arg should be a string
// like "192.0.2.1".
func (p *Pinger) RemoveIP(ipaddr string) error {
	addr := net.ParseIP(ipaddr)
	if addr == nil {
		return fmt.Errorf("%s is not a valid textual representation of an IP address", ipaddr)
	}
	p.mu.Lock()
	delete(p.addrs, addr.String())
	p.mu.Unlock()
	return nil
}

// RemoveIPAddr removes an IP address from Pinger. ip arg should be a net.IPAddr
// pointer.
func (p *Pinger) RemoveIPAddr(ip *net.IPAddr) {
	p.mu.Lock()
	delete(p.addrs, ip.String())
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

func (p *Pinger) listen(netProto string, source string) *icmp.PacketConn {
	conn, err := icmp.ListenPacket(netProto, source)
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
	var conn, conn6 *icmp.PacketConn
	if p.hasIPv4 {
		if conn = p.listen(ipv4Proto[p.network], p.source); conn == nil {
			return
		}
		defer conn.Close()
	}

	if p.hasIPv6 {
		if conn6 = p.listen(ipv6Proto[p.network], p.source6); conn6 == nil {
			return
		}
		defer conn6.Close()
	}

	recvCtx := newContext()
	wg := new(sync.WaitGroup)

	p.debugln("Run(): call recvICMP()")
	if conn != nil {
		p.mu.Lock()
		routines := p.NumGoroutines
		p.mu.Unlock()
		wg.Add(routines)
		for i := 0; i < routines; i++ {
			go p.recvICMP(conn, recvCtx, wg)
		}
	}

	if conn6 != nil {
		p.mu.Lock()
		routines := p.NumGoroutines
		p.mu.Unlock()
		wg.Add(routines)
		for i := 0; i < routines; i++ {
			go p.recvICMP(conn6, recvCtx, wg)
		}
	}

	p.debugln("Run(): call sendICMP()")
	err := p.sendICMP(conn, conn6)

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
			err = p.sendICMP(conn, conn6)
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

func (p *Pinger) sendICMP(conn, conn6 *icmp.PacketConn) error {
	type sendResult struct {
		addr *net.IPAddr
		err  error
	}

	p.debugln("sendICMP(): Start")

	p.mu.Lock()
	p.id = rand.Intn(0xffff)
	p.seq = rand.Intn(0xffff)
	p.sent = make(map[string]*net.IPAddr)
	p.mu.Unlock()

	addrs := make(chan *net.IPAddr)
	results := make(chan sendResult, 1)
	errors := make(chan []error)

	collectResult := func(results <-chan sendResult, errors chan<- []error) {
		var errs []error
		for r := range results {
			if r.err != nil {
				errs = append(errs, r.err)
			} else {
				p.mu.Lock()
				p.sent[r.addr.String()] = r.addr
				p.mu.Unlock()
			}
		}
		errors <- errs
	}
	go collectResult(results, errors)

	wg := new(sync.WaitGroup)
	sendPacket := func(addrs <-chan *net.IPAddr, results chan<- sendResult) {
		defer wg.Done()
		p.debugln("sendICMP(): Invoke sender goroutine")
		for addr := range addrs {
			var typ icmp.Type
			var cn *icmp.PacketConn
			if isIPv4(addr.IP) {
				typ = ipv4.ICMPTypeEcho
				cn = conn
			} else if isIPv6(addr.IP) {
				typ = ipv6.ICMPTypeEchoRequest
				cn = conn6
			} else {
				continue
			}
			if cn == nil {
				continue
			}

			t := timeToBytes(time.Now())

			if p.Size-TimeSliceLength != 0 {
				t = append(t, byteSliceOfSize(p.Size-TimeSliceLength)...)
			}

			p.mu.Lock()
			bytes, err := (&icmp.Message{
				Type: typ, Code: 0,
				Body: &icmp.Echo{
					ID: p.id, Seq: p.seq,
					Data: t,
				},
			}).Marshal(nil)
			p.mu.Unlock()
			if err != nil {
				p.debugln("sendICMP(): End sender goroutine with error")
				results <- sendResult{addr: nil, err: err}
				return
			}

			var dst net.Addr = addr
			if p.network == "udp" {
				dst = &net.UDPAddr{IP: addr.IP, Zone: addr.Zone}
			}

			p.debugln("sendICMP(): WriteTo Start")
			for {
				if _, err := cn.WriteTo(bytes, dst); err != nil {
					if neterr, ok := err.(*net.OpError); ok {
						if neterr.Err == syscall.ENOBUFS {
							continue
						}
					}
				}
				break
			}
			p.debugln("sendICMP(): WriteTo End")
			results <- sendResult{addr: addr, err: nil}
		}
		p.debugln("sendICMP(): End sender goroutine")
	}

	p.mu.Lock()
	routines := p.NumGoroutines
	p.mu.Unlock()
	wg.Add(routines)
	for i := 0; i < routines; i++ {
		go sendPacket(addrs, results)
	}

	for _, addr := range p.addrs {
		addrs <- addr
	}

	close(addrs)
	wg.Wait()
	close(results)
	errs := <-errors

	p.debugln("sendICMP(): End")
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

func (p *Pinger) recvICMP(conn *icmp.PacketConn, ctx *context, wg *sync.WaitGroup) {
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
		p.debugln("recvICMP(): ReadFrom Start")
		_, ra, err := conn.ReadFrom(bytes)
		p.debugln("recvICMP(): ReadFrom End")
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
		p.procRecv(bytes, ra)
	}
}

func (p *Pinger) procRecv(bytes []byte, ra net.Addr) {
	var ipaddr *net.IPAddr
	switch adr := ra.(type) {
	case *net.IPAddr:
		ipaddr = adr
	case *net.UDPAddr:
		ipaddr = &net.IPAddr{IP: adr.IP, Zone: adr.Zone}
	default:
		return
	}

	addr := ipaddr.String()
	p.mu.Lock()
	if _, ok := p.addrs[addr]; !ok {
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()

	var proto int
	if isIPv4(ipaddr.IP) {
		if p.network == "ip" {
			bytes = ipv4Payload(bytes)
		}
		proto = ProtocolICMP
	} else if isIPv6(ipaddr.IP) {
		proto = ProtocolIPv6ICMP
	} else {
		return
	}

	var m *icmp.Message
	var err error
	if m, err = icmp.ParseMessage(proto, bytes); err != nil {
		return
	}

	if m.Type != ipv4.ICMPTypeEchoReply && m.Type != ipv6.ICMPTypeEchoReply {
		return
	}

	var rtt time.Duration
	switch pkt := m.Body.(type) {
	case *icmp.Echo:
		p.mu.Lock()
		if pkt.ID == p.id && pkt.Seq == p.seq {
			rtt = time.Since(bytesToTime(pkt.Data[:TimeSliceLength]))
		}
		p.mu.Unlock()
	default:
		return
	}

	p.mu.Lock()
	if _, ok := p.sent[addr]; ok {
		delete(p.sent, addr)
		handler := p.OnRecv
		p.mu.Unlock()
		if handler != nil {
			handler(ipaddr, rtt)
		}
	} else {
		p.mu.Unlock()
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
