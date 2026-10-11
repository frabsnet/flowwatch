// FlowWatch by Frabs.net: see which VMs on a hypervisor are sending unusual
// outbound traffic. https://frabs.net
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/frabsnet/flowwatch/internal/collect"
	"github.com/frabsnet/flowwatch/internal/inventory"
	"github.com/frabsnet/flowwatch/internal/model"
	"github.com/frabsnet/flowwatch/internal/ui"
)

var version = "0.2.0"

const usage = `FlowWatch by Frabs.net %s · https://frabs.net
See which VMs on this server are sending unusual outbound traffic.

Usage:
  flowwatch                 live dashboard (run as root for destinations)
  flowwatch report          measure, then print a report
  flowwatch vms             list the VMs and interfaces FlowWatch found
  flowwatch version

Options (dashboard and report):
  -interval 5s              length of each measurement window
  -sample 1                 keep 1 in N packet headers (raise on very busy hosts)
  -counters-only            interface counters only, no packet headers
  -top 10                   destinations kept per VM

Report options:
  -duration 30s             how long to measure
  -format table|json|csv
  -o file                   write to a file instead of the terminal

FlowWatch reads hypervisor configuration, interface counters and packet
headers (never payloads, never anything inside a VM), and changes nothing.
For continuous monitoring, incidents and automatic response, see frabs.net.
`

func main() {
	cmd := "top"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	fs.Usage = func() { fmt.Fprintf(os.Stderr, usage, version) }
	interval := fs.Duration("interval", 5*time.Second, "")
	sample := fs.Int("sample", 1, "")
	countersOnly := fs.Bool("counters-only", false, "")
	top := fs.Int("top", 10, "")
	duration := fs.Duration("duration", 30*time.Second, "")
	format := fs.String("format", "table", "")
	out := fs.String("o", "", "")
	_ = fs.Parse(args)

	node, _ := os.Hostname()
	opt := collect.Options{Sample: *sample, TopN: *top, NoFlows: *countersOnly}
	switch cmd {
	case "version", "-v", "--version":
		fmt.Printf("FlowWatch by Frabs.net %s (https://frabs.net)\n", version)
	case "help", "-h", "--help":
		fs.Usage()
	case "vms":
		platform, vms := inventory.Discover(node)
		fmt.Printf("FlowWatch by Frabs.net · %s · %s%s\n\n", node, platform, panelSuffix())
		for _, vm := range vms {
			var ifs []string
			for _, i := range vm.Interfaces {
				ifs = append(ifs, i.Name)
			}
			fmt.Printf("%-36s %-24s %-32s %s\n", vm.Key.String(), vm.Name, strings.Join(ifs, ","), strings.Join(vm.IPs, ","))
		}
		if len(vms) == 0 {
			fmt.Println("No VMs found. FlowWatch looks for Proxmox, libvirt (Virtualizor, VirtFusion, SolusVM) and Xen guests, and tap/vnet/veth/vif interfaces.")
		}
	case "report":
		os.Exit(report(node, opt, *interval, *duration, *format, *out))
	case "top":
		os.Exit(dashboard(node, opt, *interval))
	default:
		fs.Usage()
		os.Exit(2)
	}
}

func panelSuffix() string {
	if p := inventory.Panel(); p != "" {
		return " (" + p + ")"
	}
	return ""
}

func report(node string, opt collect.Options, interval, duration time.Duration, format, out string) int {
	if format != "table" && format != "json" && format != "csv" {
		fmt.Fprintf(os.Stderr, "flowwatch: unknown format %q (use table, json or csv)\n", format)
		return 2
	}
	platform, vms := inventory.Discover(node)
	c := collect.New(opt)
	c.SetVMs(vms)
	c.Prime()
	if interval > duration {
		interval = duration
	}
	fmt.Fprintf(os.Stderr, "FlowWatch by Frabs.net: measuring %d VMs on %s for %s…\n", len(vms), node, duration)
	var snaps []model.Snapshot
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		time.Sleep(min(interval, time.Until(deadline)))
		snaps = append(snaps, c.Window(node, platform, version))
	}
	c.Close()
	w := os.Stdout
	if out != "" {
		f, err := os.Create(out)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer f.Close()
		w = f
	}
	var err error
	switch format {
	case "json":
		err = ui.JSON(w, snaps)
	case "csv":
		err = ui.CSV(w, snaps)
	default:
		err = table(w, merge(snaps))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if out != "" {
		fmt.Fprintf(os.Stderr, "Report written to %s\n", out)
	}
	return 0
}

// merge folds the windows into one summary per VM: totals and peaks.
func merge(snaps []model.Snapshot) model.Snapshot {
	if len(snaps) == 0 {
		return model.Snapshot{}
	}
	out := snaps[len(snaps)-1]
	out.Start = snaps[0].Start
	byKey := map[string]*model.VMStats{}
	var order []string
	for _, s := range snaps {
		for _, v := range s.VMs {
			k := v.VM.Key.String()
			m := byKey[k]
			if m == nil {
				cp := v
				cp.OutBytes, cp.InBytes = 0, 0
				m = &cp
				byKey[k] = m
				order = append(order, k)
			}
			m.OutBytes += v.OutBytes
			m.InBytes += v.InBytes
			m.OutBps = max(m.OutBps, v.OutBps)
			m.NewConns = max(m.NewConns, v.NewConns)
			m.UniqueDstIPs = max(m.UniqueDstIPs, v.UniqueDstIPs)
			m.UniqueDstPort = max(m.UniqueDstPort, v.UniqueDstPort)
			if len(v.Top) > 0 && (len(m.Top) == 0 || v.Top[0].Bytes > m.Top[0].Bytes) {
				m.Top = v.Top
			}
		}
	}
	out.VMs = nil
	for _, k := range order {
		out.VMs = append(out.VMs, *byKey[k])
	}
	ui.Sort(out.VMs, "out")
	return out
}

func table(w *os.File, s model.Snapshot) error {
	fmt.Fprintf(w, "FlowWatch by Frabs.net · %s · %s%s · %s to %s\n\n", s.Node, s.Platform, panelSuffix(), s.Start.Format("15:04:05"), s.End.Format("15:04:05"))
	fmt.Fprintf(w, "%-34s %12s %12s %12s %10s %6s  %s\n", "VM", "PEAK OUT", "SENT", "RECEIVED", "PEAK CONN", "DSTS", "TOP DESTINATION")
	for _, v := range s.VMs {
		name := v.VM.Key.ID
		if len(v.VM.IPs) > 0 {
			name += " " + v.VM.IPs[0]
		}
		top := ""
		if len(v.Top) > 0 {
			top = fmt.Sprintf("%s %s/%d", v.Top[0].IP, v.Top[0].Proto, v.Top[0].Port)
		}
		fmt.Fprintf(w, "%-34.34s %12s %12s %12s %10.0f %6d  %s\n", name, ui.Rate(v.OutBps), ui.Bytes(v.OutBytes), ui.Bytes(v.InBytes), v.NewConns, v.UniqueDstIPs, top)
	}
	for _, wn := range s.Warnings {
		fmt.Fprintf(w, "\n! %s", wn)
	}
	fmt.Fprintf(w, "\n%s\n", ui.Footer)
	return nil
}

func dashboard(node string, opt collect.Options, interval time.Duration) int {
	platform, vms := inventory.Discover(node)
	panel := inventory.Panel()
	c := collect.New(opt)
	c.SetVMs(vms)
	c.Prime()
	restore, err := ui.Raw()
	if err != nil {
		fmt.Fprintln(os.Stderr, "flowwatch: the dashboard needs a terminal; try `flowwatch report`.")
		return 1
	}
	defer restore()
	defer c.Close()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGWINCH)
	keys := ui.Keys()
	st := &ui.State{SortBy: "out"}
	// Show the VMs straight away; numbers fill in after the first window.
	snap := model.Snapshot{Node: node, Platform: platform, Warnings: []string{"Measuring the first window…"}}
	for _, vm := range vms {
		snap.VMs = append(snap.VMs, model.VMStats{VM: vm})
	}
	ui.Draw(os.Stdout, snap, panel, st, version)
	tick := time.NewTicker(interval)
	defer tick.Stop()
	rescan := time.NewTicker(60 * time.Second)
	defer rescan.Stop()
	sorts := []string{"out", "in", "conns"}
	for {
		select {
		case s := <-sig:
			if s == syscall.SIGWINCH {
				ui.Draw(os.Stdout, snap, panel, st, version)
				continue
			}
			return 0
		case <-rescan.C:
			_, vms = inventory.Discover(node)
			c.SetVMs(vms)
		case <-tick.C:
			next := c.Window(node, platform, version)
			if !st.Paused {
				snap = next
			}
		case k, ok := <-keys:
			if !ok {
				return 0
			}
			key := string(k)
			if st.Typing {
				switch {
				case key == "\r" || key == "\n":
					st.Typing = false
				case key == "\x1b":
					st.Typing, st.Filter = false, ""
				case key == "\x7f" || key == "\b":
					if len(st.Filter) > 0 {
						st.Filter = st.Filter[:len(st.Filter)-1]
					}
				case len(key) == 1 && key[0] >= 32:
					st.Filter += key
				}
				st.Selected = 0
				break
			}
			switch key {
			case "q", "\x03":
				return 0
			case "\x1b[A", "k":
				if st.Selected > 0 {
					st.Selected--
				}
			case "\x1b[B", "j":
				st.Selected++
			case "\r", "\n":
				st.Detail = true
			case "\x1b", "\x7f":
				st.Detail = false
			case "s":
				for i, s := range sorts {
					if s == st.SortBy {
						st.SortBy = sorts[(i+1)%len(sorts)]
						break
					}
				}
			case "/":
				st.Typing, st.Detail = true, false
			case "p":
				st.Paused = !st.Paused
			}
		}
		ui.Draw(os.Stdout, snap, panel, st, version)
	}
}
