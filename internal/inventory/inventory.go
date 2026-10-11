// Package inventory finds the VMs on this host and the host-side network
// interface of each. It only reads hypervisor configuration and kernel tables
// (never anything inside a guest) and changes nothing.
package inventory

import (
	"bufio"
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/frabsnet/flowwatch/internal/model"
)

// Root lets tests point discovery at a fake filesystem.
var Root = "/"

func p(parts ...string) string { return filepath.Join(append([]string{Root}, parts...)...) }

// Discover returns the platform name and every VM with at least one interface present on the host.
func Discover(node string) (string, []model.VM) {
	present := hostInterfaces()
	arp := arpTable()
	var vms []model.VM
	platform := "generic"
	claimed := map[string]bool{}
	add := func(vm model.VM) {
		var ifs []model.Interface
		for _, i := range vm.Interfaces {
			if present[i.Name] && !claimed[i.Name] {
				claimed[i.Name] = true
				ifs = append(ifs, i)
				if ip := arp[strings.ToLower(i.MAC)]; ip != "" && !contains(vm.IPs, ip) {
					vm.IPs = append(vm.IPs, ip)
				}
			}
		}
		if len(ifs) == 0 {
			return
		}
		vm.Interfaces = ifs
		vms = append(vms, vm)
	}
	if pve := proxmox(node); pve != nil {
		platform = "proxmox"
		for _, vm := range pve {
			add(vm)
		}
	}
	if lv := libvirt(node); lv != nil {
		if platform == "generic" {
			platform = "libvirt"
		}
		for _, vm := range lv {
			add(vm)
		}
	}
	if xv := xen(node); xv != nil {
		if platform == "generic" {
			platform = "xen"
		}
		for _, vm := range xv {
			add(vm)
		}
	}
	// Anything that still looks like a guest interface is shown by its name.
	guest := regexp.MustCompile(`^(tap|vnet|veth|vif|viif|kvm|macvtap)`)
	for name := range present {
		if !claimed[name] && guest.MatchString(name) && !strings.HasPrefix(name, "vethbr") {
			add(model.VM{Key: model.VMKey{Node: node, Platform: "generic", ID: name}, Interfaces: []model.Interface{{Name: name}}})
		}
	}
	sort.Slice(vms, func(a, b int) bool { return vms[a].Key.String() < vms[b].Key.String() })
	return platform, vms
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func hostInterfaces() map[string]bool {
	out := map[string]bool{}
	ents, _ := os.ReadDir(p("sys/class/net"))
	for _, e := range ents {
		out[e.Name()] = true
	}
	return out
}

// arpTable maps MAC → IPv4 from the kernel's neighbour table.
func arpTable() map[string]string {
	out := map[string]string{}
	f, err := os.Open(p("proc/net/arp"))
	if err != nil {
		return out
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Scan() // header
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) >= 4 && f[3] != "00:00:00:00:00:00" {
			out[strings.ToLower(f[3])] = f[0]
		}
	}
	return out
}

// ---- Proxmox VE: /etc/pve/qemu-server/<id>.conf → tap<id>i<n>, /etc/pve/lxc/<id>.conf → veth<id>i<n>

var (
	netLine = regexp.MustCompile(`^net(\d+):\s*(.*)$`)
	macRe   = regexp.MustCompile(`(?i)([0-9a-f]{2}(:[0-9a-f]{2}){5})`)
	ipRe    = regexp.MustCompile(`(?:^|,)ip=([0-9.]+)`)
)

func proxmox(node string) []model.VM {
	if _, err := os.Stat(p("etc/pve")); err != nil {
		return nil
	}
	var out []model.VM
	for _, kind := range []struct{ dir, platform, prefix, nameKey string }{
		{"etc/pve/qemu-server", "proxmox-qemu", "tap", "name"},
		{"etc/pve/lxc", "proxmox-lxc", "veth", "hostname"},
	} {
		files, _ := filepath.Glob(p(kind.dir, "*.conf"))
		for _, f := range files {
			id := strings.TrimSuffix(filepath.Base(f), ".conf")
			vm := model.VM{Key: model.VMKey{Node: node, Platform: kind.platform, ID: id}}
			readConf(f, func(k, v string) {
				switch {
				case k == kind.nameKey:
					vm.Name = v
				case netLine.MatchString(k + ": " + v):
					n := netLine.FindStringSubmatch(k + ": " + v)[1]
					i := model.Interface{Name: kind.prefix + id + "i" + n, MAC: strings.ToLower(macRe.FindString(v))}
					for _, part := range strings.Split(v, ",") {
						if strings.HasPrefix(part, "bridge=") {
							i.Bridge = strings.TrimPrefix(part, "bridge=")
						}
					}
					if m := ipRe.FindStringSubmatch(v); m != nil {
						vm.IPs = append(vm.IPs, m[1])
					}
					vm.Interfaces = append(vm.Interfaces, i)
				case strings.HasPrefix(k, "ipconfig"):
					if m := ipRe.FindStringSubmatch(v); m != nil {
						vm.IPs = append(vm.IPs, m[1])
					}
				}
			})
			out = append(out, vm)
		}
	}
	return out
}

// readConf reads "key: value" lines up to the first [snapshot] section.
func readConf(path string, fn func(k, v string)) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "[") {
			return
		}
		if k, v, ok := strings.Cut(line, ":"); ok && !strings.HasPrefix(line, "#") {
			fn(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
}

// Panel names the hosting panel managing this server, if any, from its install markers.
func Panel() string {
	for _, m := range []struct{ path, name string }{
		{"usr/local/virtualizor", "Virtualizor"}, {"etc/virtualizor", "Virtualizor"},
		{"opt/virtfusion", "VirtFusion"}, {"usr/local/virtfusion", "VirtFusion"},
		{"usr/local/solus", "SolusVM"}, {"etc/solus", "SolusVM"}, {"var/lib/solus", "SolusVM"}, {"usr/bin/solus-agent", "SolusVM 2"},
		{"etc/pve", "Proxmox VE"},
	} {
		if _, err := os.Stat(p(m.path)); err == nil {
			return m.name
		}
	}
	return ""
}

// ---- Xen: `xl list` gives domain IDs and names; interfaces are vif<domid>.<n> (Virtualizor Xen: viif<id>)

func xen(node string) []model.VM {
	out, err := exec.Command("xl", "list").Output()
	if err != nil {
		return nil
	}
	present := hostInterfaces()
	var vms []model.VM
	for _, line := range strings.Split(string(out), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 2 || f[1] == "0" {
			continue
		}
		vm := model.VM{Key: model.VMKey{Node: node, Platform: "xen", ID: f[0]}, Name: f[0]}
		for n := 0; n < 8; n++ {
			if name := "vif" + f[1] + "." + strconv.Itoa(n); present[name] {
				vm.Interfaces = append(vm.Interfaces, model.Interface{Name: name})
			}
		}
		vms = append(vms, vm)
	}
	return vms
}

// ---- libvirt (also Virtualizor, VirtFusion and SolusVM KVM): running domains' status XML

type lvDomain struct {
	Name  string `xml:"name"`
	UUID  string `xml:"uuid"`
	Title string `xml:"title"`
	Ifs   []struct {
		MAC struct {
			Address string `xml:"address,attr"`
		} `xml:"mac"`
		Target struct {
			Dev string `xml:"dev,attr"`
		} `xml:"target"`
		Source struct {
			Bridge string `xml:"bridge,attr"`
		} `xml:"source"`
	} `xml:"devices>interface"`
}

func libvirt(node string) []model.VM {
	files, _ := filepath.Glob(p("run/libvirt/qemu", "*.xml"))
	if len(files) == 0 {
		return nil
	}
	var out []model.VM
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var st struct {
			Domain lvDomain `xml:"domain"`
		}
		d := &st.Domain
		if xml.Unmarshal(b, &st) != nil || d.Name == "" {
			var plain lvDomain
			if xml.Unmarshal(b, &plain) != nil || plain.Name == "" {
				continue
			}
			d = &plain
		}
		vm := model.VM{Key: model.VMKey{Node: node, Platform: "libvirt", ID: d.Name}, Name: d.Title}
		for _, i := range d.Ifs {
			if i.Target.Dev != "" {
				vm.Interfaces = append(vm.Interfaces, model.Interface{Name: i.Target.Dev, MAC: strings.ToLower(i.MAC.Address), Bridge: i.Source.Bridge})
			}
		}
		out = append(out, vm)
	}
	return out
}
