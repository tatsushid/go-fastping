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
	"math/rand"
	"net"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	// TimeSliceLength lenght of time slice in bytes
	TimeSliceLength = 8
	// ProtocolICMP id of ICMP ip proto
	ProtocolICMP = 1
	// ProtocolIPv6ICMP id of ICMPv6 ip proto
	ProtocolIPv6ICMP = 58
)

var (
	ipv4Proto = map[string]string{"ip": "ip4:icmp", "udp": "udp4"}
	ipv6Proto = map[string]string{"ip": "ip6:ipv6-icmp", "udp": "udp6"}
)

func timeToBytes(t time.Time) []byte {
	var result [8]byte
	*(*int64)(unsafe.Pointer(&result[0])) = t.UnixNano()
	return result[:]
}

func bytesToTime(b []byte) time.Time {
	var nsec int64
	// better to check, but for performance reason we'll not do this
	nsec = *(*int64)(unsafe.Pointer(&b[0]))
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
	done    bool

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
	OnIdle func(map[string]*net.IPAddr)
	// NumGoroutines defines how many goroutines are used when sending ICMP
	// packets and receiving IPv4/IPv6 ICMP responses. Its default is
	// runtime.NumCPU().
	NumGoroutines int
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
	if source == p.source {
		return p.source, nil
	}

	// using ipv4 previous value for new empty one
	origSource := p.source
	if "" == source {
		p.source = ""
		p.source6 = ""
		return origSource, nil
	}

	addr := net.ParseIP(source)
	if addr == nil {
		return origSource, errors.New(source + " is not a valid textual representation of an IPv4/IPv6 address")
	}

	if isIPv4(addr) {
		p.source = source
	} else if isIPv6(addr) {
		origSource = p.source6
		p.source6 = source
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
	p.addrs[addr.String()] = &net.IPAddr{IP: addr}
	if isIPv4(addr) {
		p.hasIPv4 = true
	} else if isIPv6(addr) {
		p.hasIPv6 = true
	}
	return nil
}

// AddIPAddr adds an IP address to Pinger. ip arg should be a net.IPAddr
// pointer.
func (p *Pinger) AddIPAddr(ip *net.IPAddr) {
	p.addrs[ip.String()] = ip
	if isIPv4(ip.IP) {
		p.hasIPv4 = true
	} else if isIPv6(ip.IP) {
		p.hasIPv6 = true
	}
}

// RemoveIP removes an IP address from Pinger. ipaddr arg should be a string
// like "192.0.2.1".
func (p *Pinger) RemoveIP(ipaddr string) error {
	addr := net.ParseIP(ipaddr)
	if addr == nil {
		return fmt.Errorf("%s is not a valid textual representation of an IP address", ipaddr)
	}
	delete(p.addrs, addr.String())
	return nil
}

// RemoveIPAddr removes an IP address from Pinger. ip arg should be a net.IPAddr
// pointer.
func (p *Pinger) RemoveIPAddr(ip *net.IPAddr) {
	delete(p.addrs, ip.String())
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
			p.OnRecv = hdl
			return nil
		}
		return errors.New("receive event handler should be `func(*net.IPAddr, time.Duration)`")
	case "idle":
		if hdl, ok := handler.(func(map[string]*net.IPAddr)); ok {
			p.OnIdle = hdl
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
// an error value. It means it blocks until MaxRTT seconds passed.
func (p *Pinger) Run() error {
	p.ctx = newContext()
	p.run()
	return p.ctx.err
}

func (p *Pinger) listen(netProto string, source string) *icmp.PacketConn {
	conn, err := icmp.ListenPacket(netProto, source)
	if err != nil {
		p.ctx.err = err
		close(p.ctx.done)
		return nil
	}
	return conn
}

func (p *Pinger) run() {
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

	if conn != nil {
		routines := p.NumGoroutines
		wg.Add(routines)
		for i := 0; i < routines; i++ {
			go p.recvICMP(conn, recvCtx, wg)
		}
	}

	if conn6 != nil {
		routines := p.NumGoroutines
		wg.Add(routines)
		for i := 0; i < routines; i++ {
			go p.recvICMP(conn6, recvCtx, wg)
		}
	}

	err := p.sendICMP(conn, conn6)

	ticker := time.NewTicker(p.MaxRTT)

	select {
	case <-recvCtx.done:
		err = recvCtx.err
	case <-ticker.C:
	}

	ticker.Stop()

	close(recvCtx.stop)
	wg.Wait()

	p.ctx.err = err

	close(p.ctx.done)

	if p.OnIdle != nil {
		p.OnIdle(p.sent)
	}
}

func (p *Pinger) sendICMP(conn, conn6 *icmp.PacketConn) error {
	type sendResult struct {
		addr *net.IPAddr
		err  error
	}

	p.id = rand.Intn(0xffff)
	p.seq = rand.Intn(0xffff)
	p.sent = make(map[string]*net.IPAddr)

	addrs := make(chan *net.IPAddr)
	results := make(chan sendResult, 1)
	errors := make(chan []error)

	collectErrors := func(results <-chan sendResult, errors chan<- []error) {
		var errs []error
		for r := range results {
			errs = append(errs, r.err)
		}
		errors <- errs
	}
	go collectErrors(results, errors)

	wg := new(sync.WaitGroup)
	sendPacket := func(addrs <-chan *net.IPAddr, results chan<- sendResult) {
		defer wg.Done()

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
				t = append(t, make([]byte, p.Size-TimeSliceLength)...)
			}

			bytes, err := (&icmp.Message{
				Type: typ, Code: 0,
				Body: &icmp.Echo{
					ID: p.id, Seq: p.seq,
					Data: t,
				},
			}).Marshal(nil)

			if err != nil {
				results <- sendResult{addr: nil, err: err}
				return
			}

			var dst net.Addr = addr
			if p.network == "udp" {
				dst = &net.UDPAddr{IP: addr.IP, Zone: addr.Zone}
			}

			// pre-add ip to sent
			addrString := addr.String()
			p.mu.Lock()
			p.sent[addrString] = addr
			p.mu.Unlock()

			for {
				if _, err := cn.WriteTo(bytes, dst); err != nil {
					if neterr, ok := err.(*net.OpError); ok {
						if neterr.Err == syscall.ENOBUFS {
							continue
						} else {
							// remove ip from `sent` list if not ok
							p.mu.Lock()
							delete(p.sent, addrString)
							p.mu.Unlock()
						}
					}
				}
				break
			}
		}
	}

	wg.Add(p.NumGoroutines)
	for i := 0; i < p.NumGoroutines; i++ {
		go sendPacket(addrs, results)
	}

	for _, addr := range p.addrs {
		addrs <- addr
	}

	close(addrs)
	wg.Wait()
	close(results)
	errs := <-errors

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

func (p *Pinger) recvICMP(conn *icmp.PacketConn, ctx *context, wg *sync.WaitGroup) {

	for {
		select {
		case <-ctx.stop:
			wg.Done()
			return
		default:
		}

		bytes := make([]byte, 512)
		conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100))

		_, ra, err := conn.ReadFrom(bytes)

		if err != nil {
			if neterr, ok := err.(*net.OpError); ok {
				if neterr.Timeout() {
					continue
				} else {
					// prevent 2x close in different threads
					p.mu.Lock()
					if ctx.err == nil {
						close(ctx.done)
					}
					ctx.err = err
					p.mu.Unlock()
					wg.Done()
					return
				}
			}
		}
		p.procRecv(bytes, ra, ctx)
	}
}

func (p *Pinger) procRecv(bytes []byte, ra net.Addr, ctx *context) {
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
	_, ok := p.addrs[addr]
	p.mu.Unlock()

	if !ok {
		return
	}

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
		if pkt.ID == p.id && pkt.Seq == p.seq {
			rtt = time.Since(bytesToTime(pkt.Data[:TimeSliceLength]))
		}
	default:
		return
	}

	p.mu.Lock()
	delete(p.sent, addr)
	if len(p.sent) == 0 && !p.done {
		p.done = true
		close(ctx.done)
	}
	p.mu.Unlock()

	if p.OnRecv != nil {
		p.OnRecv(ipaddr, rtt)
	}
}
