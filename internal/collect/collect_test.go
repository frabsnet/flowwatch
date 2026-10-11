package collect

import (
	"encoding/binary"
	"testing"
)

func ipv4TCP(dst [4]byte, port uint16, flags byte) []byte {
	b := make([]byte, 14+20+20)
	binary.BigEndian.PutUint16(b[12:], 0x0800)
	ip := b[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], 40)
	ip[9] = 6
	copy(ip[16:20], dst[:])
	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[2:], port)
	tcp[13] = flags
	return b
}

func TestParseTCPSyn(t *testing.T) {
	k, n, syn, ok := parse(ipv4TCP([4]byte{198, 51, 100, 7}, 25, 0x02))
	if !ok || !syn || n != 40 || k.port != 25 || k.proto != 6 || k.ip.String() != "198.51.100.7" {
		t.Fatalf("got %+v len=%d syn=%v ok=%v", k, n, syn, ok)
	}
	if _, _, syn, _ := parse(ipv4TCP([4]byte{1, 1, 1, 1}, 443, 0x12)); syn {
		t.Fatal("SYN+ACK counted as a new connection")
	}
}

func TestParseVLAN(t *testing.T) {
	inner := ipv4TCP([4]byte{203, 0, 113, 9}, 80, 0x02)
	b := append(append(append([]byte{}, inner[:12]...), 0x81, 0x00, 0x00, 0x64), inner[12:]...)
	k, _, _, ok := parse(b)
	if !ok || k.port != 80 || k.ip.String() != "203.0.113.9" {
		t.Fatalf("VLAN-tagged frame parsed as %+v ok=%v", k, ok)
	}
}

func TestFilterSampling(t *testing.T) {
	if len(filter(1)) != 4 || len(filter(10)) != 8 {
		t.Fatalf("unexpected filter lengths %d, %d", len(filter(1)), len(filter(10)))
	}
}
