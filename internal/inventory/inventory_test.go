package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiscover(t *testing.T) {
	Root = t.TempDir()
	defer func() { Root = "/" }()
	for _, i := range []string{"tap101i0", "veth204i0", "vnet3", "vmbr0", "vif9.0"} {
		write(t, filepath.Join(Root, "sys/class/net", i, "ifindex"), "1")
	}
	write(t, filepath.Join(Root, "etc/pve/qemu-server/101.conf"), "name: web1\nnet0: virtio=BC:24:11:AA:BB:CC,bridge=vmbr0\nipconfig0: ip=203.0.113.10/24,gw=203.0.113.1\n[snap1]\nnet1: virtio=BC:24:11:00:00:01,bridge=vmbr0\n")
	write(t, filepath.Join(Root, "etc/pve/lxc/204.conf"), "hostname: ct204\nnet0: name=eth0,bridge=vmbr0,hwaddr=BC:24:11:DD:EE:FF,ip=203.0.113.20/24,type=veth\n")
	write(t, filepath.Join(Root, "run/libvirt/qemu/v1003.xml"), `<domstatus><domain type="kvm"><name>v1003</name><devices><interface type="bridge"><mac address="52:54:00:12:34:56"/><source bridge="viifbr0"/><target dev="vnet3"/></interface></devices></domain></domstatus>`)
	write(t, filepath.Join(Root, "proc/net/arp"), "IP address HW type Flags HW address Mask Device\n203.0.113.30 0x1 0x2 52:54:00:12:34:56 * viifbr0\n")

	platform, vms := Discover("hv1")
	if platform != "proxmox" {
		t.Fatalf("platform = %q", platform)
	}
	got := map[string][]string{}
	for _, vm := range vms {
		var names []string
		for _, i := range vm.Interfaces {
			names = append(names, i.Name)
		}
		got[vm.Key.String()] = append(names, vm.IPs...)
	}
	want := map[string][]string{
		"hv1/proxmox-qemu/101": {"tap101i0", "203.0.113.10"},
		"hv1/proxmox-lxc/204":  {"veth204i0", "203.0.113.20"},
		"hv1/libvirt/v1003":    {"vnet3", "203.0.113.30"},
		"hv1/generic/vif9.0":   {"vif9.0"},
	}
	for k, w := range want {
		if g := got[k]; len(g) != len(w) || g[0] != w[0] || g[len(g)-1] != w[len(w)-1] {
			t.Errorf("%s: got %v, want %v", k, g, w)
		}
	}
	if len(vms) != len(want) {
		t.Errorf("found %d VMs, want %d: %v", len(vms), len(want), got)
	}
}
