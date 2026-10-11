// Package ui draws the live terminal dashboard with plain ANSI escapes (no
// dependencies), and writes JSON and CSV reports.
package ui

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/frabsnet/flowwatch/internal/model"
)

const (
	Brand    = "FlowWatch by Frabs.net"
	BrandURL = "https://frabs.net"
	Footer   = "Continuous monitoring, incidents and automatic response: frabs.net"
)

// Bits per second, human readable.
func Rate(bps float64) string {
	u := []string{"bps", "Kbps", "Mbps", "Gbps", "Tbps"}
	i := 0
	for bps >= 1000 && i < len(u)-1 {
		bps /= 1000
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f %s", bps, u[i])
	}
	return fmt.Sprintf("%.1f %s", bps, u[i])
}

func Bytes(b uint64) string {
	f := float64(b)
	u := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	for f >= 1000 && i < len(u)-1 {
		f /= 1000
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f %s", f, u[i])
	}
	return fmt.Sprintf("%.1f %s", f, u[i])
}

// ---- terminal

type termios syscall.Termios

func ioctl(fd, req uintptr, arg unsafe.Pointer) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(arg)); e != 0 {
		return e
	}
	return nil
}

// Raw puts the terminal in raw mode and returns a restore function.
func Raw() (func(), error) {
	var old termios
	if err := ioctl(0, syscall.TCGETS, unsafe.Pointer(&old)); err != nil {
		return nil, err
	}
	raw := old
	raw.Lflag &^= syscall.ECHO | syscall.ICANON
	raw.Cc[syscall.VMIN] = 1
	raw.Cc[syscall.VTIME] = 0
	if err := ioctl(0, syscall.TCSETS, unsafe.Pointer(&raw)); err != nil {
		return nil, err
	}
	fmt.Print("\x1b[?1049h\x1b[?25l")
	return func() {
		fmt.Print("\x1b[?25h\x1b[?1049l")
		_ = ioctl(0, syscall.TCSETS, unsafe.Pointer(&old))
	}, nil
}

func Size() (int, int) {
	var ws struct{ Row, Col, X, Y uint16 }
	if ioctl(1, syscall.TIOCGWINSZ, unsafe.Pointer(&ws)) != nil || ws.Col == 0 {
		return 120, 40
	}
	return int(ws.Col), int(ws.Row)
}

// ---- dashboard

const (
	bold  = "\x1b[1m"
	dim   = "\x1b[2m"
	teal  = "\x1b[38;5;37m"
	red   = "\x1b[38;5;203m"
	amber = "\x1b[38;5;214m"
	inv   = "\x1b[7m"
	reset = "\x1b[0m"
)

// State is what the viewer has chosen.
type State struct {
	Selected int
	Detail   bool
	SortBy   string // out, in, conns, flags
	Filter   string
	Typing   bool
	Paused   bool
}

func Sort(vms []model.VMStats, by string) {
	sort.SliceStable(vms, func(a, b int) bool {
		switch by {
		case "in":
			return vms[a].InBps > vms[b].InBps
		case "conns":
			return vms[a].NewConns > vms[b].NewConns
		case "flags":
			return len(vms[a].Indicators) > len(vms[b].Indicators)
		}
		return vms[a].OutBps > vms[b].OutBps
	})
}

func Filter(vms []model.VMStats, q string) []model.VMStats {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return vms
	}
	var out []model.VMStats
	for _, v := range vms {
		hay := strings.ToLower(v.VM.Key.String() + " " + v.VM.Name + " " + strings.Join(v.VM.IPs, " "))
		if strings.Contains(hay, q) {
			out = append(out, v)
		}
	}
	return out
}

func pad(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		if n <= 1 {
			return string(r[:n])
		}
		return string(r[:n-1]) + "…"
	}
	return s + strings.Repeat(" ", n-len(r))
}
func lpad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return strings.Repeat(" ", n-len(s)) + s
}

// Draw renders one frame.
func Draw(w io.Writer, snap model.Snapshot, panel string, st *State, version string) {
	cols, rows := Size()
	var b strings.Builder
	b.WriteString("\x1b[H\x1b[2J")
	var totOut, totIn float64
	flagged := 0
	for _, v := range snap.VMs {
		totOut += v.OutBps
		totIn += v.InBps
		if len(v.Indicators) > 0 {
			flagged++
		}
	}
	where := snap.Platform
	if panel != "" {
		where = panel
	}
	fmt.Fprintf(&b, "%s%s FlowWatch %s%s by Frabs.net%s  %sv%s%s\x1b[%dG%s%s%s\r\n", teal, bold, reset, bold, reset, dim, version, reset, max(1, cols-len(snap.Node)-len(where)-3), dim, snap.Node+" · "+where, reset)
	flagColour := ""
	if flagged > 0 {
		flagColour = red
	}
	fmt.Fprintf(&b, "%sOut%s %-12s %sIn%s %-12s %sVMs%s %-5d %sFlagged%s %s%d%s", dim, reset, Rate(totOut), dim, reset, Rate(totIn), dim, reset, len(snap.VMs), dim, reset, flagColour, flagged, reset)
	if st.Paused {
		fmt.Fprintf(&b, "   %sPAUSED%s", amber, reset)
	}
	b.WriteString("\r\n")
	for _, w := range snap.Warnings {
		fmt.Fprintf(&b, "%s! %s%s\r\n", amber, w, reset)
	}
	b.WriteString("\r\n")

	vms := Filter(append([]model.VMStats(nil), snap.VMs...), st.Filter)
	Sort(vms, st.SortBy)
	if st.Selected >= len(vms) {
		st.Selected = max(0, len(vms)-1)
	}
	body := rows - 6 - len(snap.Warnings)
	if st.Detail && len(vms) > 0 {
		drawDetail(&b, vms[st.Selected], cols, body)
	} else {
		nameW := max(16, cols-82)
		head := fmt.Sprintf("%s %s %s %s %s %s %s  %s", pad("VM", nameW), lpad("OUT", 11), lpad("IN", 11), lpad("OUT PPS", 9), lpad("CONN/S", 7), lpad("DSTS", 6), lpad("PORTS", 6), "FLAGS")
		fmt.Fprintf(&b, "%s%s%s\r\n", dim, pad(head, cols), reset)
		start := 0
		if st.Selected >= body-1 {
			start = st.Selected - body + 2
		}
		for i := start; i < len(vms) && i-start < body-1; i++ {
			v := vms[i]
			name := v.VM.Key.ID
			if v.VM.Name != "" && v.VM.Name != v.VM.Key.ID {
				name += " " + v.VM.Name
			}
			if len(v.VM.IPs) > 0 {
				name += "  " + v.VM.IPs[0]
			}
			flags := ""
			if len(v.Indicators) > 0 {
				flags = red + v.Indicators[0].Kind + reset
				if len(v.Indicators) > 1 {
					flags += dim + fmt.Sprintf(" +%d", len(v.Indicators)-1) + reset
				}
			}
			conns := "-"
			if v.Sampled {
				conns = strconv.FormatFloat(v.NewConns, 'f', 0, 64)
			}
			line := fmt.Sprintf("%s %s %s %s %s %s %s  ", pad(name, nameW), lpad(Rate(v.OutBps), 11), lpad(Rate(v.InBps), 11), lpad(strconv.FormatFloat(v.OutPps, 'f', 0, 64), 9), lpad(conns, 7), lpad(strconv.Itoa(v.UniqueDstIPs), 6), lpad(strconv.Itoa(v.UniqueDstPort), 6))
			if i == st.Selected {
				fmt.Fprintf(&b, "%s%s%s%s\r\n", inv, line, reset, flags)
			} else {
				fmt.Fprintf(&b, "%s%s\r\n", line, flags)
			}
		}
		if len(vms) == 0 && st.Filter != "" {
			fmt.Fprintf(&b, "%s  No VMs match %q%s\r\n", dim, st.Filter, reset)
		} else if len(vms) == 0 {
			fmt.Fprintf(&b, "%s  No VMs found. FlowWatch looks for Proxmox, libvirt and Xen guests and tap/vnet/veth/vif interfaces.%s\r\n", dim, reset)
		}
	}
	// footer
	keys := "↑↓ select · enter details · s sort (" + st.SortBy + ") · / search · p pause · q quit"
	if st.Typing {
		keys = "search: " + st.Filter + "█  (enter to keep, esc to clear)"
	}
	fmt.Fprintf(&b, "\x1b[%d;1H%s%s%s\r\n%s%s%s", rows-1, dim, pad(keys, cols), reset, teal, pad(Footer, cols), reset)
	io.WriteString(w, b.String())
}

func drawDetail(b *strings.Builder, v model.VMStats, cols, body int) {
	fmt.Fprintf(b, "%s%s%s  %s%s%s\r\n", bold, v.VM.Key.String(), reset, dim, v.VM.Name, reset)
	var ifs []string
	for _, i := range v.VM.Interfaces {
		ifs = append(ifs, i.Name)
	}
	fmt.Fprintf(b, "%sIPs%s %s   %sInterfaces%s %s\r\n", dim, reset, strings.Join(v.VM.IPs, ", "), dim, reset, strings.Join(ifs, ", "))
	fmt.Fprintf(b, "%sOut%s %s (%s)  %sIn%s %s (%s)  %sNew conns/s%s %.0f  %sDestinations%s %d  %sPorts%s %d\r\n\r\n", dim, reset, Rate(v.OutBps), Bytes(v.OutBytes), dim, reset, Rate(v.InBps), Bytes(v.InBytes), dim, reset, v.NewConns, dim, reset, v.UniqueDstIPs, dim, reset, v.UniqueDstPort)
	if len(v.Indicators) > 0 {
		fmt.Fprintf(b, "%sINDICATORS%s\r\n", dim, reset)
		for _, i := range v.Indicators {
			fmt.Fprintf(b, "  %s%-11s%s %s\r\n", red, i.Kind, reset, i.Detail)
		}
		b.WriteString("\r\n")
	}
	if !v.Sampled {
		fmt.Fprintf(b, "%sDestinations need root (or CAP_NET_RAW).%s\r\n", dim, reset)
		return
	}
	fmt.Fprintf(b, "%s%s%s\r\n", dim, pad(fmt.Sprintf("%-40s %-6s %7s %12s %12s", "TOP DESTINATIONS", "PROTO", "PORT", "PACKETS", "BYTES"), cols), reset)
	for _, d := range v.Top {
		fmt.Fprintf(b, "%-40s %-6s %7d %12d %12s\r\n", d.IP, d.Proto, d.Port, d.Packets, Bytes(d.Bytes))
	}
	fmt.Fprintf(b, "\r\n%sesc back%s\r\n", dim, reset)
}

// ---- reports

type report struct {
	Generator string           `json:"generator"`
	Snapshots []model.Snapshot `json:"windows"`
}

func JSON(w io.Writer, snaps []model.Snapshot) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(report{Generator: Brand + " (" + BrandURL + ")", Snapshots: snaps})
}

func CSV(w io.Writer, snaps []model.Snapshot) error {
	fmt.Fprintf(w, "# %s (%s)\n", Brand, BrandURL)
	c := csv.NewWriter(w)
	_ = c.Write([]string{"window_end", "node", "platform", "vm_id", "vm_name", "ips", "out_bps", "in_bps", "out_bytes", "in_bytes", "out_pps", "new_conns_per_s", "unique_dst_ips", "unique_dst_ports", "indicators", "top_destination"})
	for _, s := range snaps {
		for _, v := range s.VMs {
			var ind []string
			for _, i := range v.Indicators {
				ind = append(ind, i.Kind+": "+i.Detail)
			}
			top := ""
			if len(v.Top) > 0 {
				top = fmt.Sprintf("%s %s/%d", v.Top[0].IP, v.Top[0].Proto, v.Top[0].Port)
			}
			_ = c.Write([]string{s.End.UTC().Format("2006-01-02T15:04:05Z"), v.VM.Key.Node, v.VM.Key.Platform, v.VM.Key.ID, v.VM.Name, strings.Join(v.VM.IPs, " "),
				strconv.FormatFloat(v.OutBps, 'f', 0, 64), strconv.FormatFloat(v.InBps, 'f', 0, 64), strconv.FormatUint(v.OutBytes, 10), strconv.FormatUint(v.InBytes, 10),
				strconv.FormatFloat(v.OutPps, 'f', 0, 64), strconv.FormatFloat(v.NewConns, 'f', 1, 64), strconv.Itoa(v.UniqueDstIPs), strconv.Itoa(v.UniqueDstPort), strings.Join(ind, "; "), top})
		}
	}
	c.Flush()
	return c.Error()
}

// Stdin reads one key at a time.
func Keys() <-chan []byte {
	ch := make(chan []byte)
	go func() {
		buf := make([]byte, 8)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				close(ch)
				return
			}
			ch <- append([]byte(nil), buf[:n]...)
		}
	}()
	return ch
}
