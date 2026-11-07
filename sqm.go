//go:build linux

package main

import (
	"errors"
	"fmt"
	"math"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// The shaper caps one uplink's speed in both directions, SQM style:
//
//	upload:   uplink root  -> htb 7451: (class 1 at the cap) -> fq_codel
//	download: uplink ingress -> matchall + mirred redirect -> ifb "tshield_ifb"
//	          ifb root     -> htb 7451: (class 1 at the cap) -> fq_codel
//
// While shaping, the uplink's GSO (upload) and GRO (download) packet sizes
// are capped so one aggregated packet takes about sqmAggSeconds to leave at
// the cap: HTB sends whole packets, and behind a 64 KB one at 4 Mbit/s
// everything (ACKs, game packets) would wait 130 ms. cake splits GSO
// packets for the same reason. The original sizes come back on close.
//
// Class 2 carries the delay probes (sqm_engine.go's pings), ahead of the
// bulk class and with its own small rate, so they never wait behind a
// queued 64 KB GSO/GRO packet: the delay they see is the link's, not the
// shaper's own. Upload probes reach it through their socket priority,
// download replies through u32 filters for ICMP on the ifb.
//
// The redirect is tc's mirred action, not bpf_redirect: cellular links are
// raw IP (no Ethernet header), and bpf_redirect drops such packets when the
// target (the ifb) is an Ethernet-type device; mirred hands them over as
// they are. Our handles are fixed, so we find and remove exactly what we
// added; deleting our root qdisc gives the link back its default.

const (
	sqmHandleMajor  = 0x7451
	sqmLeafMajor    = 0x7452
	sqmIfbName      = "tshield_ifb"
	sqmFilterHandle = 0x7452
	// HTB quantum: at least one GSO super-packet, so a single class never
	// loops through deficit rounds (and the kernel doesn't warn about the
	// quantum it would derive from fast rates).
	sqmQuantum = 65536
	// sqmBurstTime is how much line-rate burst the cap allows.
	sqmBurstSeconds = 0.004
	// sqmProbeKbit is the probe class's own rate: plenty for 10 pings a
	// second, too little for anyone to hide traffic in.
	sqmProbeKbit = 2000
	// sqmAggSeconds: target time for one GSO/GRO packet at the cap.
	sqmAggSeconds = 0.002
	sqmAggMin     = 2 * 1500
	sqmAggMax     = 65536
)

// sqmProbeClass is the HTB class of delay probes (also their SO_PRIORITY).
var sqmProbeClass = netlink.MakeHandle(sqmHandleMajor, 2)

// sqmFilterPrios: run our redirect first (1). netd attaches its tethering
// offload program to the same hook, and filters of different kinds can't
// share a priority; if netd holds 1, we go after it (3), which only misses
// packets netd itself offloads.
var sqmFilterPrios = []uint16{1, 3}

type shaper struct {
	n        *tcNetns
	dev, ifb netlink.Link
	// The uplink's own GSO/GRO sizes, restored on close, and ours.
	origGSO, origGRO uint32
	gso, gro         uint32
	ingress          bool // download shaping attached
	prio     uint16 // of our ingress filter
}

// newShaper shapes dev at the given caps. With ingress false only upload is
// shaped (used when the downlink can't be redirected safely, e.g. CLAT).
func newShaper(n *tcNetns, dev netlink.Link, downKbit, upKbit float64, ingress bool) (*shaper, error) {
	s := &shaper{n: n, dev: dev, origGSO: dev.Attrs().GSOMaxSize, origGRO: dev.Attrs().GROMaxSize}
	if err := s.setupHTB(dev, upKbit); err != nil {
		return nil, fmt.Errorf("upload shaper on %s: %w", dev.Attrs().Name, err)
	}
	if ingress {
		if err := s.setupIngress(downKbit); err != nil {
			s.close()
			return nil, fmt.Errorf("download shaper on %s: %w", dev.Attrs().Name, err)
		}
	}
	s.limitAggregation(downKbit, upKbit)
	return s, nil
}

// aggSize is the GSO/GRO size for a cap: sqmAggSeconds of it.
func aggSize(kbit float64) uint32 {
	return uint32(min(max(kbit*1000/8*sqmAggSeconds, sqmAggMin), sqmAggMax))
}

// limitAggregation sets the uplink's GSO and GRO sizes for the caps (never
// above what the link had). Kernels that can't change them just keep
// theirs: shaping still works, with more delay at low caps.
func (s *shaper) limitAggregation(downKbit, upKbit float64) {
	if s.origGSO > 0 {
		if gso := min(aggSize(upKbit), s.origGSO); gso != s.gso {
			if err := s.n.nl.LinkSetGSOMaxSize(s.dev, int(gso)); err == nil {
				s.gso = gso
			}
		}
	}
	if s.ingress && s.origGRO > 0 {
		if gro := min(aggSize(downKbit), s.origGRO); gro != s.gro {
			if err := s.n.nl.LinkSetGROMaxSize(s.dev, int(gro)); err == nil {
				s.gro = gro
			}
		}
	}
}

func (s *shaper) setupIngress(downKbit float64) error {
	ifb, err := ensureIfb(s.n)
	if err != nil {
		return err
	}
	s.ifb = ifb
	if err := s.setupHTB(ifb, downKbit); err != nil {
		return err
	}
	if err := s.addProbeFilters(ifb); err != nil {
		return err
	}
	if err := ensureClsact(s.n, s.dev); err != nil {
		return err
	}
	var errs []error
	for _, prio := range sqmFilterPrios {
		if err := s.n.nl.FilterReplace(s.ingressFilter(prio)); err != nil {
			errs = append(errs, fmt.Errorf("prio %d: %w", prio, err))
			continue
		}
		s.prio, s.ingress = prio, true
		return nil
	}
	return fmt.Errorf("add ingress redirect: %w", errors.Join(errs...))
}

func (s *shaper) ingressFilter(prio uint16) *netlink.MatchAll {
	return &netlink.MatchAll{
		FilterAttrs: sqmFilterAttrs(s.dev, prio),
		Actions:     []netlink.Action{netlink.NewMirredAction(s.ifb.Attrs().Index)},
	}
}

func sqmFilterAttrs(dev netlink.Link, prio uint16) netlink.FilterAttrs {
	return netlink.FilterAttrs{
		LinkIndex: dev.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0, sqmFilterHandle),
		Protocol:  unix.ETH_P_ALL,
		Priority:  prio,
	}
}

func ensureIfb(n *tcNetns) (netlink.Link, error) {
	l, err := n.nl.LinkByName(sqmIfbName)
	if err != nil {
		if err := n.nl.LinkAdd(&netlink.Ifb{LinkAttrs: netlink.LinkAttrs{Name: sqmIfbName, TxQLen: 1000}}); err != nil && !errors.Is(err, unix.EEXIST) {
			return nil, fmt.Errorf("create %s: %w", sqmIfbName, err)
		}
		if l, err = n.nl.LinkByName(sqmIfbName); err != nil {
			return nil, err
		}
	}
	if err := n.nl.LinkSetUp(l); err != nil {
		return nil, fmt.Errorf("bring up %s: %w", sqmIfbName, err)
	}
	return l, nil
}

// setupHTB replaces l's root qdisc with htb -> one class at kbit -> fq_codel.
func (s *shaper) setupHTB(l netlink.Link, kbit float64) error {
	idx := l.Attrs().Index
	root := netlink.NewHtb(netlink.QdiscAttrs{
		LinkIndex: idx,
		Handle:    netlink.MakeHandle(sqmHandleMajor, 0),
		Parent:    netlink.HANDLE_ROOT,
	})
	root.Defcls = 1
	if err := s.n.nl.QdiscReplace(root); err != nil {
		return fmt.Errorf("add htb: %w", err)
	}
	if err := s.n.nl.ClassReplace(htbClass(idx, kbit)); err != nil {
		return fmt.Errorf("add htb class: %w", err)
	}
	if err := s.n.nl.ClassReplace(probeClass(idx)); err != nil {
		return fmt.Errorf("add htb probe class: %w", err)
	}
	leaf := netlink.NewFqCodel(netlink.QdiscAttrs{
		LinkIndex: idx,
		Handle:    netlink.MakeHandle(sqmLeafMajor, 0),
		Parent:    netlink.MakeHandle(sqmHandleMajor, 1),
	})
	if err := s.n.nl.QdiscReplace(leaf); err != nil {
		return fmt.Errorf("add fq_codel: %w", err)
	}
	return nil
}

func htbClass(linkIndex int, kbit float64) *netlink.HtbClass {
	return newClass(linkIndex, netlink.MakeHandle(sqmHandleMajor, 1), kbit, 1)
}

func probeClass(linkIndex int) *netlink.HtbClass {
	return newClass(linkIndex, sqmProbeClass, sqmProbeKbit, 0)
}

func newClass(linkIndex int, handle uint32, kbit float64, prio uint32) *netlink.HtbClass {
	bits := uint64(math.Max(kbit, 1) * 1000)
	burst := uint32(math.Max(float64(bits)/8*sqmBurstSeconds, 2*1514))
	return netlink.NewHtbClass(netlink.ClassAttrs{
		LinkIndex: linkIndex,
		Parent:    netlink.MakeHandle(sqmHandleMajor, 0),
		Handle:    handle,
	}, netlink.HtbClassAttrs{Rate: bits, Ceil: bits, Buffer: burst, Cbuffer: burst, Quantum: sqmQuantum, Prio: prio})
}

// addProbeFilters sends ICMP (IPv4 protocol 1, IPv6 next header 58)
// arriving on the ifb to the probe class.
func (s *shaper) addProbeFilters(ifb netlink.Link) error {
	// One priority per protocol: filters sharing a priority must share
	// the protocol too.
	for _, f := range []struct {
		prio  uint16
		proto uint16
		key   netlink.TcU32Key
	}{
		// IPv4 word at offset 8: TTL, protocol, checksum.
		{1, unix.ETH_P_IP, netlink.TcU32Key{Mask: 0x00ff0000, Val: 0x00010000, Off: 8}},
		// IPv6 word at offset 4: payload length, next header, hop limit.
		{2, unix.ETH_P_IPV6, netlink.TcU32Key{Mask: 0x0000ff00, Val: 0x00003a00, Off: 4}},
	} {
		u := &netlink.U32{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: ifb.Attrs().Index,
				Parent:    netlink.MakeHandle(sqmHandleMajor, 0),
				Priority:  f.prio,
				Protocol:  f.proto,
			},
			ClassId: sqmProbeClass,
			Sel: &netlink.TcU32Sel{
				Flags: netlink.TC_U32_TERMINAL,
				Nkeys: 1,
				Keys:  []netlink.TcU32Key{f.key},
			},
		}
		if err := s.n.nl.FilterAdd(u); err != nil {
			return fmt.Errorf("add probe filter: %w", err)
		}
	}
	return nil
}

// setRates changes the caps in place (no packets are dropped).
func (s *shaper) setRates(downKbit, upKbit float64) error {
	if err := s.n.nl.ClassChange(htbClass(s.dev.Attrs().Index, upKbit)); err != nil {
		return fmt.Errorf("set upload cap: %w", err)
	}
	if s.ingress {
		if err := s.n.nl.ClassChange(htbClass(s.ifb.Attrs().Index, downKbit)); err != nil {
			return fmt.Errorf("set download cap: %w", err)
		}
	}
	s.limitAggregation(downKbit, upKbit)
	return nil
}

// intact reports whether everything we attached is still there (another
// tool, or netd recreating clsact, may have removed it).
func (s *shaper) intact() bool {
	if !hasSQMRoot(s.n, s.dev) {
		return false
	}
	if !s.ingress {
		return true
	}
	return hasSQMRoot(s.n, s.ifb) && hasSQMFilter(s.n, s.dev)
}

func hasSQMRoot(n *tcNetns, l netlink.Link) bool {
	qdiscs, err := n.nl.QdiscList(l)
	if err != nil {
		return false
	}
	for _, q := range qdiscs {
		a := q.Attrs()
		if a.Parent == netlink.HANDLE_ROOT && a.Handle == netlink.MakeHandle(sqmHandleMajor, 0) && q.Type() == "htb" {
			return true
		}
	}
	return false
}

// sqmFilterPrio finds our redirect among ingress filters.
func sqmFilterPrio(filters []netlink.Filter) (uint16, bool) {
	for _, f := range filters {
		if _, ok := f.(*netlink.MatchAll); ok && f.Attrs().Handle == netlink.MakeHandle(0, sqmFilterHandle) {
			return f.Attrs().Priority, true
		}
	}
	return 0, false
}

func hasSQMFilter(n *tcNetns, l netlink.Link) bool {
	filters, err := n.nl.FilterList(l, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return false
	}
	_, found := sqmFilterPrio(filters)
	return found
}

// close removes what we attached: the link gets its default qdisc back.
func (s *shaper) close() {
	removeSQM(s.n, s.dev)
	if s.gso != 0 {
		_ = s.n.nl.LinkSetGSOMaxSize(s.dev, int(s.origGSO))
	}
	if s.gro != 0 {
		_ = s.n.nl.LinkSetGROMaxSize(s.dev, int(s.origGRO))
	}
}

// removeSQM undoes a shaper on dev, whichever daemon attached it, and
// deletes the ifb. Safe to call when nothing is attached.
func removeSQM(n *tcNetns, dev netlink.Link) {
	if dev != nil {
		if filters, err := n.nl.FilterList(dev, netlink.HANDLE_MIN_INGRESS); err == nil {
			if prio, found := sqmFilterPrio(filters); found {
				_ = n.nl.FilterDel(&netlink.MatchAll{FilterAttrs: sqmFilterAttrs(dev, prio)})
			}
		}
		if hasSQMRoot(n, dev) {
			_ = n.nl.QdiscDel(&netlink.GenericQdisc{QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: dev.Attrs().Index,
				Handle:    netlink.MakeHandle(sqmHandleMajor, 0),
				Parent:    netlink.HANDLE_ROOT,
			}, QdiscType: "htb"})
		}
	}
	if l, err := n.nl.LinkByName(sqmIfbName); err == nil {
		_ = n.nl.LinkDel(l)
	}
}

// removeAllSQM undoes shapers left on any link (e.g. by a daemon that was
// killed), so a new daemon starts clean.
func removeAllSQM(n *tcNetns) {
	links, err := n.nl.LinkList()
	if err != nil {
		return
	}
	for _, l := range links {
		if l.Attrs().Name == sqmIfbName {
			continue
		}
		if hasSQMRoot(n, l) || hasSQMFilter(n, l) {
			removeSQM(n, l)
		}
	}
	if l, err := n.nl.LinkByName(sqmIfbName); err == nil {
		_ = n.nl.LinkDel(l)
	}
}
