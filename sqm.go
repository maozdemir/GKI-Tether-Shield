//go:build linux

package main

import (
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// The shaper caps one uplink's speed in both directions, SQM style:
//
//	upload:   uplink root  -> htb 7451: (one class at the cap) -> fq_codel
//	download: uplink ingress -> eBPF redirect -> ifb "tshield_ifb"
//	          ifb root     -> htb 7451: (one class at the cap) -> fq_codel
//
// The ingress redirect is a 4-instruction eBPF program built at run time
// (no compiler needed). Our handles are fixed, so we find and remove exactly
// what we added; deleting our root qdisc gives the link back its default.

const (
	sqmHandleMajor  = 0x7451
	sqmLeafMajor    = 0x7452
	sqmIfbName      = "tshield_ifb"
	sqmFilterHandle = 0x7452
	sqmFilterName   = "tshield_sqm"
	// HTB quantum: at least one GSO super-packet, so a single class never
	// loops through deficit rounds (and the kernel doesn't warn about the
	// quantum it would derive from fast rates).
	sqmQuantum = 65536
	// sqmBurstTime is how much line-rate burst the cap allows.
	sqmBurstSeconds = 0.004
)

// sqmFilterPrios: run our redirect first (1). netd attaches its tethering
// offload program to the same hook; if it took prio 1 with a filter we
// can't share it with, we go after it (3), which only misses packets netd
// itself offloads.
var sqmFilterPrios = []uint16{1, 3}

type shaper struct {
	n        *tcNetns
	dev, ifb netlink.Link
	redirect *ebpf.Program
	ingress  bool   // download shaping attached
	prio     uint16 // of our ingress filter
}

// newShaper shapes dev at the given caps. With ingress false only upload is
// shaped (used when the downlink can't be redirected safely, e.g. CLAT).
func newShaper(n *tcNetns, dev netlink.Link, downKbit, upKbit float64, ingress bool) (*shaper, error) {
	s := &shaper{n: n, dev: dev}
	if err := s.setupHTB(dev, upKbit); err != nil {
		return nil, fmt.Errorf("upload shaper on %s: %w", dev.Attrs().Name, err)
	}
	if ingress {
		if err := s.setupIngress(downKbit); err != nil {
			s.close()
			return nil, fmt.Errorf("download shaper on %s: %w", dev.Attrs().Name, err)
		}
	}
	return s, nil
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
	prog, err := loadRedirect(ifb.Attrs().Index)
	if err != nil {
		return err
	}
	s.redirect = prog
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

func (s *shaper) ingressFilter(prio uint16) *netlink.BpfFilter {
	f := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: s.dev.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0, sqmFilterHandle),
			Protocol:  unix.ETH_P_ALL,
			Priority:  prio,
		},
		Name:         sqmFilterName,
		DirectAction: true,
	}
	if s.redirect != nil {
		f.Fd = s.redirect.FD()
	}
	return f
}

// loadRedirect builds "return bpf_redirect(ifindex, 0)": every packet goes to
// the ifb's egress, which shapes it and hands it back to the stack.
func loadRedirect(ifindex int) (*ebpf.Program, error) {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "tshield_sqm",
		Type: ebpf.SchedCLS,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R1, int32(ifindex)),
			asm.Mov.Imm(asm.R2, 0),
			asm.FnRedirect.Call(),
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		return nil, fmt.Errorf("load ingress redirect program: %w", err)
	}
	return prog, nil
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
	bits := uint64(math.Max(kbit, 1) * 1000)
	burst := uint32(math.Max(float64(bits)/8*sqmBurstSeconds, 2*1514))
	return netlink.NewHtbClass(netlink.ClassAttrs{
		LinkIndex: linkIndex,
		Parent:    netlink.MakeHandle(sqmHandleMajor, 0),
		Handle:    netlink.MakeHandle(sqmHandleMajor, 1),
	}, netlink.HtbClassAttrs{Rate: bits, Ceil: bits, Buffer: burst, Cbuffer: burst, Quantum: sqmQuantum})
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

func hasSQMFilter(n *tcNetns, l netlink.Link) bool {
	filters, err := n.nl.FilterList(l, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return false
	}
	for _, f := range filters {
		bf, ok := f.(*netlink.BpfFilter)
		if ok && f.Attrs().Handle == netlink.MakeHandle(0, sqmFilterHandle) && strings.HasPrefix(bf.Name, sqmFilterName) {
			return true
		}
	}
	return false
}

// close removes what we attached: the link gets its default qdisc back.
func (s *shaper) close() {
	removeSQM(s.n, s.dev)
	if s.redirect != nil {
		s.redirect.Close()
		s.redirect = nil
	}
}

// removeSQM undoes a shaper on dev, whichever daemon attached it, and
// deletes the ifb. Safe to call when nothing is attached.
func removeSQM(n *tcNetns, dev netlink.Link) {
	if dev != nil {
		for _, prio := range sqmFilterPrios {
			if hasSQMFilter(n, dev) {
				f := &netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{
					LinkIndex: dev.Attrs().Index,
					Parent:    netlink.HANDLE_MIN_INGRESS,
					Handle:    netlink.MakeHandle(0, sqmFilterHandle),
					Protocol:  unix.ETH_P_ALL,
					Priority:  prio,
				}}
				_ = n.nl.FilterDel(f)
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
