// mtufinder - Path MTU Discovery tool.
//
// Single-file Go program (with golang.org/x/net compiled in) that discovers
// the maximum MTU along the path to a target host by binary-searching the
// size of an ICMP echo probe.
//
// For IPv4 the probe is built and sent with the "Don't Fragment" bit set
// using golang.org/x/net/ipv4.RawConn, so the IP header construction is
// pure portable Go code with no per-OS setsockopt branching. For IPv6 we
// rely on the fact that IPv6 routers never fragment in transit -- an
// oversized packet either elicits an ICMPv6 "Packet Too Big" or times out.
//
// Build:
//   go build -o mtufinder mtufinder.go
//
// Cross-compile (single static binary, no system ping dependency):
//   GOOS=linux   GOARCH=amd64 go build -o mtufinder        ./...
//   GOOS=darwin  GOARCH=arm64 go build -o mtufinder        ./...
//   GOOS=windows GOARCH=amd64 go build -o mtufinder.exe    ./...
//
// Usage:
//   sudo ./mtufinder [flags] <hostname-or-ip>
//
// Raw ICMP sockets require elevated privileges:
//   * Linux/macOS: run with sudo, or grant CAP_NET_RAW (Linux setcap).
//   * Windows: run from an elevated (Administrator) shell.
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	ipv4HeaderBytes = 20
	ipv6HeaderBytes = 40
	icmpHeaderBytes = 8

	// IPv4 minimum MTU per RFC 791.
	defaultMinV4 = 68
	// IPv6 minimum MTU per RFC 8200.
	defaultMinV6 = 1280
	// Common jumbo-frame upper bound.
	defaultMaxMTU = 9000
)

type probeResult int

const (
	probeOK probeResult = iota
	probeTooBig
	probeTimeout
	probeError
)

func (r probeResult) String() string {
	switch r {
	case probeOK:
		return "OK"
	case probeTooBig:
		return "TOO_BIG"
	case probeTimeout:
		return "TIMEOUT"
	default:
		return "ERROR"
	}
}

// prober is a uniform interface so the search loop is family-agnostic.
type prober interface {
	probe(mtu int, timeout time.Duration) (probeResult, error)
	close() error
	headerBytes() int
}

// ---------- IPv4 prober ----------

type proberV4 struct {
	rc  *ipv4.RawConn
	dst net.IP
	id  int
	seq int
}

func newProberV4(dst net.IP) (*proberV4, error) {
	pc, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("open raw ICMPv4 socket (need root/admin): %w", err)
	}
	rc, err := ipv4.NewRawConn(pc)
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("wrap raw IPv4 conn: %w", err)
	}
	return &proberV4{rc: rc, dst: dst.To4(), id: os.Getpid() & 0xffff}, nil
}

func (p *proberV4) close() error      { return p.rc.Close() }
func (p *proberV4) headerBytes() int  { return ipv4HeaderBytes }

func (p *proberV4) probe(mtu int, timeout time.Duration) (probeResult, error) {
	p.seq = (p.seq + 1) & 0xffff
	payloadLen := mtu - ipv4HeaderBytes - icmpHeaderBytes
	if payloadLen < 0 {
		return probeError, fmt.Errorf("MTU %d smaller than required headers", mtu)
	}
	data := make([]byte, payloadLen)
	for i := range data {
		data[i] = byte(i)
	}
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: p.id, Seq: p.seq, Data: data},
	}
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return probeError, err
	}
	hdr := &ipv4.Header{
		Version:  4,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + len(msgBytes),
		TTL:      64,
		Protocol: 1, // ICMP
		Flags:    ipv4.DontFragment,
		Dst:      p.dst,
	}

	deadline := time.Now().Add(timeout)
	if err := p.rc.SetWriteDeadline(deadline); err != nil {
		return probeError, err
	}
	if err := p.rc.WriteTo(hdr, msgBytes, nil); err != nil {
		if isMsgSizeErr(err) {
			return probeTooBig, nil
		}
		return probeError, err
	}

	if err := p.rc.SetReadDeadline(deadline); err != nil {
		return probeError, err
	}

	buf := make([]byte, 65535)
	for {
		_, payload, _, err := p.rc.ReadFrom(buf)
		if err != nil {
			if isTimeoutErr(err) {
				return probeTimeout, nil
			}
			return probeError, err
		}
		parsed, err := icmp.ParseMessage(1, payload) // protocol 1 = ICMPv4
		if err != nil {
			continue
		}
		switch body := parsed.Body.(type) {
		case *icmp.Echo:
			if parsed.Type == ipv4.ICMPTypeEchoReply && body.ID == p.id && body.Seq == p.seq {
				return probeOK, nil
			}
		case *icmp.DstUnreach:
			// Code 4 = Fragmentation Needed and DF set.
			if parsed.Type == ipv4.ICMPTypeDestinationUnreachable && parsed.Code == 4 {
				if matchInnerV4(body.Data, p.id, p.seq) {
					return probeTooBig, nil
				}
			}
		}
		// Other ICMP traffic on this host -- ignore and keep reading.
	}
}

// matchInnerV4 confirms an ICMP Destination Unreachable carries the embedded
// IPv4+ICMP header of OUR probe (so we don't react to another process's frag
// events arriving on this shared raw socket).
func matchInnerV4(data []byte, id, seq int) bool {
	if len(data) < 1 {
		return false
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < ipv4HeaderBytes || len(data) < ihl+8 {
		return false
	}
	inner := data[ihl:]
	innerID := int(binary.BigEndian.Uint16(inner[4:6]))
	innerSeq := int(binary.BigEndian.Uint16(inner[6:8]))
	return innerID == id && innerSeq == seq
}

// ---------- IPv6 prober ----------

type proberV6 struct {
	pc  *icmp.PacketConn
	dst net.IP
	id  int
	seq int
}

func newProberV6(dst net.IP) (*proberV6, error) {
	pc, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return nil, fmt.Errorf("open raw ICMPv6 socket (need root/admin): %w", err)
	}
	return &proberV6{pc: pc, dst: dst, id: os.Getpid() & 0xffff}, nil
}

func (p *proberV6) close() error      { return p.pc.Close() }
func (p *proberV6) headerBytes() int  { return ipv6HeaderBytes }

func (p *proberV6) probe(mtu int, timeout time.Duration) (probeResult, error) {
	p.seq = (p.seq + 1) & 0xffff
	payloadLen := mtu - ipv6HeaderBytes - icmpHeaderBytes
	if payloadLen < 0 {
		return probeError, fmt.Errorf("MTU %d smaller than required headers", mtu)
	}
	data := make([]byte, payloadLen)
	for i := range data {
		data[i] = byte(i)
	}
	msg := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{ID: p.id, Seq: p.seq, Data: data},
	}
	msgBytes, err := msg.Marshal(icmp.IPv6PseudoHeader(net.IPv6zero, p.dst))
	if err != nil {
		return probeError, err
	}

	deadline := time.Now().Add(timeout)
	if err := p.pc.SetWriteDeadline(deadline); err != nil {
		return probeError, err
	}
	if _, err := p.pc.WriteTo(msgBytes, &net.IPAddr{IP: p.dst}); err != nil {
		if isMsgSizeErr(err) {
			return probeTooBig, nil
		}
		return probeError, err
	}

	if err := p.pc.SetReadDeadline(deadline); err != nil {
		return probeError, err
	}

	buf := make([]byte, 65535)
	for {
		n, _, err := p.pc.ReadFrom(buf)
		if err != nil {
			if isTimeoutErr(err) {
				return probeTimeout, nil
			}
			return probeError, err
		}
		parsed, err := icmp.ParseMessage(58, buf[:n]) // protocol 58 = ICMPv6
		if err != nil {
			continue
		}
		switch body := parsed.Body.(type) {
		case *icmp.Echo:
			if parsed.Type == ipv6.ICMPTypeEchoReply && body.ID == p.id && body.Seq == p.seq {
				return probeOK, nil
			}
		case *icmp.PacketTooBig:
			// Could parse the embedded packet to match seq; PTB messages
			// are rare enough that any received during our window is treated
			// as authoritative for our probe.
			_ = body
			return probeTooBig, nil
		}
	}
}

// ---------- Helpers ----------

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return false
}

// isMsgSizeErr returns true when the kernel rejected a sendto because the
// packet exceeded the local interface MTU with DF set (EMSGSIZE / WSAEMSGSIZE).
func isMsgSizeErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "message too long") ||
		strings.Contains(s, "msg too long") ||
		strings.Contains(s, "message size") ||
		strings.Contains(s, "msgsize")
}

func resolveTarget(target string) (net.IP, bool, error) {
	addrs, err := net.LookupIP(target)
	if err != nil {
		return nil, false, err
	}
	for _, a := range addrs {
		if v4 := a.To4(); v4 != nil {
			return v4, false, nil
		}
	}
	for _, a := range addrs {
		if a.To16() != nil {
			return a, true, nil
		}
	}
	return nil, false, fmt.Errorf("no usable address for %s", target)
}

func probeReliable(p prober, mtu int, timeout time.Duration, retries int) probeResult {
	var last probeResult
	for i := 0; i <= retries; i++ {
		r, err := p.probe(mtu, timeout)
		if err != nil {
			last = probeError
			continue
		}
		last = r
		if r == probeOK || r == probeTooBig {
			return r
		}
		time.Sleep(150 * time.Millisecond)
	}
	return last
}

// findMTU binary-searches for the largest MTU at which the path returns an
// echo reply. A timeout is treated the same as TOO_BIG because a broken
// PMTUD path (ICMP black hole) silently drops oversize probes rather than
// returning the "Frag Needed" message.
func findMTU(p prober, lo, hi int, timeout time.Duration, verbose bool) (int, error) {
	if hi < lo {
		return 0, fmt.Errorf("invalid range: max (%d) < min (%d)", hi, lo)
	}

	if verbose {
		fmt.Printf("[*] Baseline reachability at MTU %d...\n", lo)
	}
	if probeReliable(p, lo, timeout, 3) != probeOK {
		return 0, fmt.Errorf("target unreachable at baseline MTU %d", lo)
	}

	if verbose {
		fmt.Printf("[*] Trying upper bound %d...\n", hi)
	}
	if probeReliable(p, hi, timeout, 1) == probeOK {
		if verbose {
			fmt.Printf("[+] Upper bound %d succeeded\n", hi)
		}
		return hi, nil
	}

	best := lo
	for lo <= hi {
		mid := (lo + hi) / 2
		res := probeReliable(p, mid, timeout, 1)
		if verbose {
			fmt.Printf("    probe MTU=%-5d -> %s\n", mid, res)
		}
		if res == probeOK {
			best = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	return best, nil
}

// result is what we print at the end -- as JSON if --json is set, or as a
// human-readable line otherwise. Zero-valued fields are omitted in JSON so
// failure payloads don't carry meaningless mtu=0 / family=0 noise.
type result struct {
	Success   bool   `json:"success"`
	Target    string `json:"target"`
	IP        string `json:"ip,omitempty"`
	Family    int    `json:"family,omitempty"`
	MTU       int    `json:"mtu,omitempty"`
	Min       int    `json:"min,omitempty"`
	Max       int    `json:"max,omitempty"`
	TimeoutMs int    `json:"timeout_ms,omitempty"`
	ElapsedMs int64  `json:"elapsed_ms,omitempty"`
	Error     string `json:"error,omitempty"`
}

func runProbe(target string, minMTU, maxMTU, timeoutMs int, verbose bool) result {
	start := time.Now()
	res := result{
		Target:    target,
		Max:       maxMTU,
		TimeoutMs: timeoutMs,
	}

	dst, isV6, err := resolveTarget(target)
	if err != nil {
		res.Error = fmt.Sprintf("cannot resolve %s: %v", target, err)
		res.ElapsedMs = time.Since(start).Milliseconds()
		return res
	}
	res.IP = dst.String()
	if isV6 {
		res.Family = 6
	} else {
		res.Family = 4
	}

	if minMTU == 0 {
		if isV6 {
			minMTU = defaultMinV6
		} else {
			minMTU = defaultMinV4
		}
	}
	res.Min = minMTU

	var p prober
	if isV6 {
		p, err = newProberV6(dst)
	} else {
		p, err = newProberV4(dst)
	}
	if err != nil {
		res.Error = err.Error()
		res.ElapsedMs = time.Since(start).Milliseconds()
		return res
	}
	defer p.close()

	if verbose {
		fmt.Printf("[*] Target:  %s -> %s (IPv%d)\n", target, res.IP, res.Family)
		fmt.Printf("[*] OS:      %s\n", runtime.GOOS)
		fmt.Printf("[*] Range:   %d - %d bytes\n", minMTU, maxMTU)
		fmt.Printf("[*] Timeout: %d ms/probe\n\n", timeoutMs)
	}

	timeout := time.Duration(timeoutMs) * time.Millisecond
	mtu, err := findMTU(p, minMTU, maxMTU, timeout, verbose)
	if err != nil {
		res.Error = err.Error()
		res.ElapsedMs = time.Since(start).Milliseconds()
		return res
	}

	res.MTU = mtu
	res.Success = true
	res.ElapsedMs = time.Since(start).Milliseconds()
	return res
}

func main() {
	minFlag := flag.Int("min", 0, "minimum MTU to probe (default: 68 v4 / 1280 v6)")
	maxFlag := flag.Int("max", defaultMaxMTU, "maximum MTU to probe")
	timeoutFlag := flag.Int("timeout", 2000, "per-probe timeout in milliseconds")
	quietFlag := flag.Bool("quiet", false, "suppress progress output")
	jsonFlag := flag.Bool("json", false, "emit machine-readable JSON instead of human output (implies -quiet)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "mtufinder - discover path MTU using native ICMP\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <hostname-or-ip>\n\nFlags:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nRequires elevated privileges (sudo / Administrator) for raw ICMP.\n")
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	verbose := !*quietFlag && !*jsonFlag
	res := runProbe(flag.Arg(0), *minFlag, *maxFlag, *timeoutFlag, verbose)

	if *jsonFlag {
		// Always emit JSON to stdout so callers can pipe to jq regardless of
		// success/failure. Exit code still signals success.
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else if res.Success {
		fmt.Printf("\nPath MTU to %s (%s): %d bytes\n", res.Target, res.IP, res.MTU)
	} else {
		fmt.Fprintln(os.Stderr, "error:", res.Error)
	}

	if !res.Success {
		os.Exit(1)
	}
}
