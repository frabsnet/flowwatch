// Package collect measures each VM's traffic: interface counters from the
// kernel for exact totals, plus sampled packet headers (never payloads) from
// each VM interface for destinations and connection activity.
package collect

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/frabsnet/flowwatch/internal/model"
)

// Thresholds for indicators. They flag patterns worth a look; they never block anything.
type Thresholds struct {
	ScanPorts   int     // distinct destination ports on one IP in a window
	ScanHosts   int     // distinct destination IPs on one port in a window
	SpikeFactor float64 // new connections per second vs the VM's own average
	SpikeMin    float64 // ...and at least this many per second
	FloodPps    float64 // packets per second to a single destination
	SMTPConns   float64 // new connections to port 25 per minute
}

var DefaultThresholds = Thresholds{ScanPorts: 100, ScanHosts: 200, SpikeFactor: 5, SpikeMin: 50, FloodPps: 20000, SMTPConns: 30}

// Options for a collector.
type Options struct {
	Sample     int // keep 1 in N packet headers (1 = all)
	TopN       int
	Thresholds Thresholds
	NoFlows    bool // counters only, no header sampling
}

type flowKey struct {
	ip    netip.Addr
	port  uint16
	proto uint8
}

type vmFlows struct {
	mu       sync.Mutex
	dst      map[flowKey]*[2]uint64 // packets, bytes (sampled)
	syns     uint64
	smtp     uint64
	baseline float64 // smoothed new connections per second
}

// Collector measures one host's VMs window by window.
type Collector struct {
	opt     Options
	mu      sync.Mutex
	vms     []model.VM
	flows   map[string]*vmFlows // by interface name
	vmOf    map[string]int      // interface → index into vms
	stop    map[string]chan struct{}
	last    map[string][4]uint64 // rx_bytes, tx_bytes, rx_packets, tx_packets
	lastAt  time.Time
	seq     uint64
	warn    []string
	flowsOK bool
}

func New(opt Options) *Collector {
	if opt.Sample < 1 {
		opt.Sample = 1
	}
	if opt.TopN < 1 {
		opt.TopN = 10
	}
	return &Collector{opt: opt, flows: map[string]*vmFlows{}, vmOf: map[string]int{}, stop: map[string]chan struct{}{}, last: map[string][4]uint64{}, flowsOK: !opt.NoFlows}
}

// SetVMs updates the VM list; sampling starts on new interfaces and stops on gone ones.
func (c *Collector) SetVMs(vms []model.VM) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.vms = vms
	c.vmOf = map[string]int{}
	want := map[string]bool{}
	for i, vm := range vms {
		for _, itf := range vm.Interfaces {
			c.vmOf[itf.Name] = i
			want[itf.Name] = true
			if _, ok := c.flows[itf.Name]; !ok {
				c.flows[itf.Name] = &vmFlows{dst: map[flowKey]*[2]uint64{}}
				if c.flowsOK {
					ch := make(chan struct{})
					c.stop[itf.Name] = ch
					go c.sample(itf.Name, c.flows[itf.Name], ch)
				}
			}
		}
	}
	for name, ch := range c.stop {
		if !want[name] {
			close(ch)
			delete(c.stop, name)
			delete(c.flows, name)
		}
	}
}

// Close stops all sampling.
func (c *Collector) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for name, ch := range c.stop {
		close(ch)
		delete(c.stop, name)
	}
}

func counters(iface string) ([4]uint64, bool) {
	var v [4]uint64
	for i, f := range []string{"rx_bytes", "tx_bytes", "rx_packets", "tx_packets"} {
		b, err := os.ReadFile("/sys/class/net/" + iface + "/statistics/" + f)
		if err != nil {
			return v, false
		}
		v[i], _ = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	}
	return v, true
}

// Prime takes the first counter reading so the first window has rates.
func (c *Collector) Prime() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for name := range c.vmOf {
		if v, ok := counters(name); ok {
			c.last[name] = v
		}
	}
	c.lastAt = time.Now()
}

// Window closes the current window and returns it.
func (c *Collector) Window(node, platform, version string) model.Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	secs := now.Sub(c.lastAt).Seconds()
	if secs <= 0 {
		secs = 1
	}
	c.seq++
	snap := model.Snapshot{Schema: model.SchemaVersion, Node: node, Platform: platform, Version: version, Seq: c.seq, Start: c.lastAt, End: now, Warnings: append([]string(nil), c.warn...)}
	stats := make([]model.VMStats, len(c.vms))
	for i, vm := range c.vms {
		stats[i] = model.VMStats{VM: vm, Sampled: c.flowsOK}
	}
	merged := make([]map[flowKey]*[2]uint64, len(c.vms))
	syns := make([]uint64, len(c.vms))
	smtp := make([]uint64, len(c.vms))
	for name, i := range c.vmOf {
		if v, ok := counters(name); ok {
			if old, had := c.last[name]; had && v[0] >= old[0] && v[1] >= old[1] {
				// On the host side of a VM's interface, rx is what the VM sent.
				st := &stats[i]
				st.OutBytes += v[0] - old[0]
				st.InBytes += v[1] - old[1]
				st.OutPps += float64(v[2]-old[2]) / secs
				st.InPps += float64(v[3]-old[3]) / secs
			}
			c.last[name] = v
		}
		f := c.flows[name]
		if f == nil {
			continue
		}
		f.mu.Lock()
		if merged[i] == nil {
			merged[i] = map[flowKey]*[2]uint64{}
		}
		for k, v := range f.dst {
			m := merged[i][k]
			if m == nil {
				m = &[2]uint64{}
				merged[i][k] = m
			}
			m[0] += v[0]
			m[1] += v[1]
		}
		syns[i] += f.syns
		smtp[i] += f.smtp
		f.dst = map[flowKey]*[2]uint64{}
		f.syns, f.smtp = 0, 0
		f.mu.Unlock()
	}
	scale := float64(c.opt.Sample)
	th := c.opt.Thresholds
	for i := range stats {
		st := &stats[i]
		st.OutBps = float64(st.OutBytes) * 8 / secs
		st.InBps = float64(st.InBytes) * 8 / secs
		if merged[i] == nil {
			continue
		}
		ips := map[netip.Addr]map[uint16]bool{}
		ports := map[uint16]map[netip.Addr]bool{}
		var list []model.Destination
		var newUDP uint64
		for k, v := range merged[i] {
			if ips[k.ip] == nil {
				ips[k.ip] = map[uint16]bool{}
			}
			ips[k.ip][k.port] = true
			if k.port != 0 {
				if ports[k.port] == nil {
					ports[k.port] = map[netip.Addr]bool{}
				}
				ports[k.port][k.ip] = true
			}
			if k.proto == 17 {
				newUDP++
			}
			list = append(list, model.Destination{IP: k.ip.String(), Port: k.port, Proto: protoName(k.proto), Packets: uint64(float64(v[0]) * scale), Bytes: uint64(float64(v[1]) * scale)})
		}
		st.UniqueDstIPs = len(ips)
		st.UniqueDstPort = len(ports)
		st.NewConns = (float64(syns[i])*scale + float64(newUDP)) / secs
		sort.Slice(list, func(a, b int) bool { return list[a].Bytes > list[b].Bytes })
		if len(list) > c.opt.TopN {
			list = list[:c.opt.TopN]
		}
		st.Top = list
		// Indicators.
		for ip, ps := range ips {
			if len(ps) >= th.ScanPorts {
				st.Indicators = append(st.Indicators, model.Indicator{Kind: "port_scan", Detail: fmt.Sprintf("%d ports on %s", len(ps), ip), Value: float64(len(ps))})
			}
		}
		for port, hs := range ports {
			if len(hs) >= th.ScanHosts {
				st.Indicators = append(st.Indicators, model.Indicator{Kind: "host_scan", Detail: fmt.Sprintf("%d hosts on port %d", len(hs), port), Value: float64(len(hs))})
			}
		}
		for _, d := range list {
			if pps := float64(d.Packets) / secs; pps >= th.FloodPps {
				st.Indicators = append(st.Indicators, model.Indicator{Kind: "flood", Detail: fmt.Sprintf("%.0f pps to %s %s/%d", pps, d.IP, d.Proto, d.Port), Value: pps})
			}
		}
		if perMin := float64(smtp[i]) * scale / secs * 60; perMin >= th.SMTPConns {
			st.Indicators = append(st.Indicators, model.Indicator{Kind: "smtp_burst", Detail: fmt.Sprintf("%.0f new SMTP connections a minute", perMin), Value: perMin})
		}
		f := c.flows[st.VM.Interfaces[0].Name]
		if f != nil {
			if f.baseline > 0 && st.NewConns >= th.SpikeMin && st.NewConns >= f.baseline*th.SpikeFactor {
				st.Indicators = append(st.Indicators, model.Indicator{Kind: "conn_spike", Detail: fmt.Sprintf("%.0f new connections/s, usually %.0f", st.NewConns, f.baseline), Value: st.NewConns})
			}
			if f.baseline == 0 {
				f.baseline = st.NewConns
			} else {
				f.baseline = f.baseline*0.9 + st.NewConns*0.1
			}
		}
		sort.Slice(st.Indicators, func(a, b int) bool { return st.Indicators[a].Value > st.Indicators[b].Value })
	}
	sort.Slice(stats, func(a, b int) bool { return stats[a].OutBps > stats[b].OutBps })
	snap.VMs = stats
	c.lastAt = now
	return snap
}

func protoName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1, 58:
		return "icmp"
	}
	return strconv.Itoa(int(p))
}

// ---- header sampling (AF_PACKET, headers only)

func htons(v uint16) uint16 { return v<<8 | v>>8 }

type sockFilter struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}
type sockFprog struct {
	Len    uint16
	_      [6]byte
	Filter *sockFilter
}

// filter keeps frames the VM sent (not ones the host sends to it), one in
// `sample`, and only the first 128 bytes: headers, never payloads.
func filter(sample int) []sockFilter {
	const (
		ldPkttype = 0x20 // BPF_LD|BPF_W|BPF_ABS
		jeqK      = 0x15
		ret       = 0x06
		modK      = 0x94
	)
	f := []sockFilter{
		{Code: ldPkttype, K: 0xfffff004}, // SKF_AD_OFF + SKF_AD_PKTTYPE
		{Code: jeqK, Jt: 0, Jf: 1, K: 4}, // PACKET_OUTGOING → drop
		{Code: ret, K: 0},
	}
	if sample > 1 {
		f = append(f,
			sockFilter{Code: ldPkttype, K: 0xfffff038}, // SKF_AD_RANDOM
			sockFilter{Code: modK, K: uint32(sample)},
			sockFilter{Code: jeqK, Jt: 1, Jf: 0, K: 0},
			sockFilter{Code: ret, K: 0},
		)
	}
	return append(f, sockFilter{Code: ret, K: 128})
}

func (c *Collector) note(msg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, w := range c.warn {
		if w == msg {
			return
		}
	}
	c.warn = append(c.warn, msg)
}

func (c *Collector) sample(iface string, f *vmFlows, stop chan struct{}) {
	ifi, err := netInterfaceIndex(iface)
	if err != nil {
		return
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		c.note("Destinations need root (or CAP_NET_RAW); showing counters only.")
		return
	}
	defer syscall.Close(fd)
	prog := filter(c.opt.Sample)
	fp := sockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if _, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), syscall.SOL_SOCKET, syscall.SO_ATTACH_FILTER, uintptr(unsafe.Pointer(&fp)), unsafe.Sizeof(fp), 0); e != 0 {
		c.note("Could not attach the packet filter; showing counters only.")
		return
	}
	tv := syscall.Timeval{Sec: 0, Usec: 500000}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: ifi}); err != nil {
		return
	}
	buf := make([]byte, 256)
	for {
		select {
		case <-stop:
			return
		default:
		}
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil || n < 14 {
			continue
		}
		if ll, ok := from.(*syscall.SockaddrLinklayer); !ok || ll.Ifindex != ifi {
			continue
		}
		k, length, syn, ok := parse(buf[:n])
		if !ok {
			continue
		}
		f.mu.Lock()
		v := f.dst[k]
		if v == nil {
			if len(f.dst) >= 50000 { // bounded memory, even under a scan
				f.mu.Unlock()
				continue
			}
			v = &[2]uint64{}
			f.dst[k] = v
		}
		v[0]++
		v[1] += uint64(length)
		if syn {
			f.syns++
			if k.port == 25 {
				f.smtp++
			}
		}
		f.mu.Unlock()
	}
}

// parse reads Ethernet (with VLAN tags), IPv4/IPv6 and the TCP/UDP header.
func parse(b []byte) (k flowKey, length int, syn bool, ok bool) {
	off := 12
	et := binary.BigEndian.Uint16(b[off:])
	off += 2
	for (et == 0x8100 || et == 0x88a8) && len(b) >= off+4 {
		et = binary.BigEndian.Uint16(b[off+2:])
		off += 4
	}
	var l4 int
	switch et {
	case 0x0800:
		if len(b) < off+20 {
			return
		}
		ihl := int(b[off]&0x0f) * 4
		length = int(binary.BigEndian.Uint16(b[off+2:]))
		k.proto = b[off+9]
		k.ip = netip.AddrFrom4([4]byte(b[off+16 : off+20]))
		if binary.BigEndian.Uint16(b[off+6:])&0x1fff != 0 { // later fragment: no ports
			return k, length, false, true
		}
		l4 = off + ihl
	case 0x86dd:
		if len(b) < off+40 {
			return
		}
		length = int(binary.BigEndian.Uint16(b[off+4:])) + 40
		k.proto = b[off+6]
		k.ip = netip.AddrFrom16([16]byte(b[off+24 : off+40]))
		l4 = off + 40
	default:
		return
	}
	if (k.proto == 6 || k.proto == 17) && len(b) >= l4+4 {
		k.port = binary.BigEndian.Uint16(b[l4+2:])
		if k.proto == 6 && len(b) >= l4+14 {
			flags := b[l4+13]
			syn = flags&0x02 != 0 && flags&0x10 == 0
		}
	}
	return k, length, syn, true
}

func netInterfaceIndex(name string) (int, error) {
	b, err := os.ReadFile("/sys/class/net/" + name + "/ifindex")
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}
