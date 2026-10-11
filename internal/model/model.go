// Package model holds the data FlowWatch measures and exchanges. It is the
// same shape in standalone mode and (later) between agents and a master, so a
// VM is always identified by node + platform + local ID: VM IDs repeat across
// hypervisors, the triple does not.
package model

import "time"

// SchemaVersion changes whenever a field changes meaning.
const SchemaVersion = 1

type VMKey struct {
	Node     string `json:"node"`
	Platform string `json:"platform"` // proxmox-qemu, proxmox-lxc, libvirt, generic
	ID       string `json:"id"`
}

func (k VMKey) String() string { return k.Node + "/" + k.Platform + "/" + k.ID }

type Interface struct {
	Name   string `json:"name"`
	MAC    string `json:"mac,omitempty"`
	Bridge string `json:"bridge,omitempty"`
}

type VM struct {
	Key        VMKey       `json:"key"`
	Name       string      `json:"name,omitempty"`
	IPs        []string    `json:"ips,omitempty"`
	Interfaces []Interface `json:"interfaces"`
}

// Destination is one remote endpoint a VM talked to in the window.
type Destination struct {
	IP      string `json:"ip"`
	Port    uint16 `json:"port,omitempty"`
	Proto   string `json:"proto"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type VMStats struct {
	VM            VM            `json:"vm"`
	OutBps        float64       `json:"out_bps"` // bits per second leaving the VM
	InBps         float64       `json:"in_bps"`
	OutPps        float64       `json:"out_pps"`
	InPps         float64       `json:"in_pps"`
	OutBytes      uint64        `json:"out_bytes"` // in the window
	InBytes       uint64        `json:"in_bytes"`
	NewConns      float64       `json:"new_conns_per_s"` // TCP SYNs + new UDP flows per second (sampled)
	UniqueDstIPs  int           `json:"unique_dst_ips"`
	UniqueDstPort int           `json:"unique_dst_ports"`
	Top           []Destination `json:"top_destinations,omitempty"`
	Sampled       bool          `json:"flows_sampled"` // false when header sampling is unavailable
}

// Snapshot is one node's view of one measurement window.
type Snapshot struct {
	Schema   int       `json:"schema"`
	Node     string    `json:"node"`
	Platform string    `json:"platform"`
	Version  string    `json:"flowwatch_version"`
	Seq      uint64    `json:"seq"` // increases by one per window; lets a master spot gaps and replays
	Start    time.Time `json:"window_start"`
	End      time.Time `json:"window_end"`
	VMs      []VMStats `json:"vms"`
	Warnings []string  `json:"warnings,omitempty"`
}
