//go:build linux

package main

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Our tc egress filter. A fixed handle and priority let us find, replace and
// remove exactly our filter without touching the ones Android's netd and
// clatd attach to the same hooks. Priority 1 runs first, before CLAT's
// egress program translates and redirects IPv4.
const (
	ttlFilterHandle = 0x7451
	ttlFilterPrio   = 1
	ttlFilterName   = "tshield_ttl"
	// ttlResyncEvery re-checks attachments in case netd recreated a qdisc.
	ttlResyncEvery = 5 * time.Second
)

// downstreamIfacePatterns mirrors DOWNSTREAM_IFACES in service.sh: local and
// tethering (downstream) interfaces. Every other interface is an upstream
// and gets the program. A trailing '+' matches any suffix, as in iptables.
var downstreamIfacePatterns = []string{
	"lo", "wlan+", "swlan+", "ap+", "softap+", "p2p+", "wigig+",
	"rndis+", "ncm+", "usb+", "bt-pan+", "eth+",
}

// isDownstreamIface reports whether name matches a downstream pattern.
func isDownstreamIface(name string) bool {
	for _, p := range downstreamIfacePatterns {
		if prefix, ok := strings.CutSuffix(p, "+"); ok {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		} else if name == p {
			return true
		}
	}
	return false
}

// rawIPLink reports whether packets on link start at the IP header (no
// Ethernet header): cellular rmnet / ccmni, CLAT v4-*, tun and ppp.
func rawIPLink(l netlink.Link) bool {
	return l.Attrs().EncapType != "ether"
}

// tcNetns is a netlink handle bound to one network namespace. Its sockets
// stay in that namespace whichever goroutine (OS thread) uses them.
type tcNetns struct {
	nl *netlink.Handle
	ns netns.NsHandle
}

// currentTCNetns binds to the calling thread's network namespace.
func currentTCNetns() (*tcNetns, error) {
	ns, err := netns.Get()
	if err != nil {
		return nil, fmt.Errorf("get network namespace: %w", err)
	}
	nl, err := netlink.NewHandleAt(ns)
	if err != nil {
		ns.Close()
		return nil, fmt.Errorf("open netlink: %w", err)
	}
	return &tcNetns{nl: nl, ns: ns}, nil
}

func (t *tcNetns) close() {
	t.nl.Close()
	t.ns.Close()
}

// tcAttacher keeps our program attached to the egress of every upstream
// interface that is up.
type tcAttacher struct {
	progs *ttlProgSet
	net   *tcNetns
	ids   map[int]bool // kernel IDs of our loaded programs

	mu       sync.Mutex
	attached map[int]string // ifindex -> name
	stop     chan struct{}
	done     chan struct{}
}

func newTCAttacher(progs *ttlProgSet, n *tcNetns) *tcAttacher {
	ids := map[int]bool{}
	for _, p := range []*ebpf.Program{progs.raw, progs.eth} {
		if info, err := p.Info(); err == nil {
			if id, ok := info.ID(); ok {
				ids[int(id)] = true
			}
		}
	}
	return &tcAttacher{progs: progs, net: n, ids: ids, attached: map[int]string{}}
}

// start attaches to the current upstreams, then follows link changes until
// stopped. It fails if the first sync can't attach anywhere because of an
// error (no upstream at all is fine: one may come up later).
func (a *tcAttacher) start() error {
	if err := a.sync(); err != nil {
		return err
	}
	a.stop = make(chan struct{})
	a.done = make(chan struct{})
	go a.follow()
	return nil
}

func (a *tcAttacher) follow() {
	defer close(a.done)
	updates := make(chan netlink.LinkUpdate, 32)
	ns := a.net.ns
	opts := netlink.LinkSubscribeOptions{Namespace: &ns}
	if err := netlink.LinkSubscribeWithOptions(updates, a.stop, opts); err != nil {
		updates = nil // fall back to the periodic resync only
	}
	tick := time.NewTicker(ttlResyncEvery)
	defer tick.Stop()
	for {
		select {
		case <-a.stop:
			return
		case <-tick.C:
		case _, ok := <-updates:
			if !ok {
				updates = nil
				continue
			}
		}
		if err := a.sync(); err != nil {
			logf("eBPF: %v", err)
		}
	}
}

// sync attaches to upstream links that are up and lack our filter, and
// forgets links that went away. It returns an error only when every attach
// attempt failed.
func (a *tcAttacher) sync() error {
	links, err := a.net.nl.LinkList()
	if err != nil {
		return fmt.Errorf("list links: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	present := map[int]bool{}
	var errs []error
	attachedAny := false
	for _, l := range links {
		attrs := l.Attrs()
		if attrs.Flags&net.FlagUp == 0 || isDownstreamIface(attrs.Name) {
			continue
		}
		present[attrs.Index] = true
		if hasTTLFilter(a.net, l, a.ids) {
			attachedAny = true
			continue
		}
		if err := a.attach(l); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", attrs.Name, err))
			delete(present, attrs.Index)
			continue
		}
		attachedAny = true
		if a.attached[attrs.Index] != attrs.Name {
			logf("eBPF: TTL program attached to %s", attrs.Name)
		}
		a.attached[attrs.Index] = attrs.Name
	}
	for idx := range a.attached {
		if !present[idx] {
			delete(a.attached, idx)
		}
	}
	if len(errs) > 0 && !attachedAny {
		return fmt.Errorf("attach failed: %w", errors.Join(errs...))
	}
	for _, e := range errs {
		logf("eBPF: %v", e)
	}
	return nil
}

func ttlFilterAttrs(l netlink.Link) netlink.FilterAttrs {
	return netlink.FilterAttrs{
		LinkIndex: l.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, ttlFilterHandle),
		Protocol:  unix.ETH_P_ALL,
		Priority:  ttlFilterPrio,
	}
}

// hasTTLFilter reports whether our filter is on l's egress hook. With ids
// set, it must also run one of those programs: a filter left by an earlier
// daemon uses its old maps, so it gets replaced.
func hasTTLFilter(n *tcNetns, l netlink.Link, ids map[int]bool) bool {
	filters, err := n.nl.FilterList(l, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return false
	}
	want := netlink.MakeHandle(0, ttlFilterHandle)
	for _, f := range filters {
		bf, ok := f.(*netlink.BpfFilter)
		if !ok || f.Attrs().Handle != want || !strings.HasPrefix(bf.Name, ttlFilterName) {
			continue
		}
		if ids == nil || ids[bf.Id] {
			return true
		}
	}
	return false
}

// attach adds a clsact qdisc if the link has none (never replacing an
// existing one, which would drop netd's filters) and installs our filter.
func (a *tcAttacher) attach(l netlink.Link) error {
	if err := ensureClsact(a.net, l); err != nil {
		return err
	}
	prog := a.progs.eth
	if rawIPLink(l) {
		prog = a.progs.raw
	}
	f := &netlink.BpfFilter{
		FilterAttrs:  ttlFilterAttrs(l),
		Fd:           prog.FD(),
		Name:         ttlFilterName,
		DirectAction: true,
	}
	if err := a.net.nl.FilterReplace(f); err != nil {
		return fmt.Errorf("add tc filter: %w", err)
	}
	return nil
}

func ensureClsact(n *tcNetns, l netlink.Link) error {
	qdiscs, err := n.nl.QdiscList(l)
	if err != nil {
		return fmt.Errorf("list qdiscs: %w", err)
	}
	for _, q := range qdiscs {
		if q.Type() == "clsact" {
			return nil
		}
	}
	q := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: l.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := n.nl.QdiscAdd(q); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("add clsact qdisc: %w", err)
	}
	return nil
}

// close stops following links and removes our filter from every link that
// still has it. The clsact qdisc stays: netd may be using it.
func (a *tcAttacher) close() {
	if a.stop != nil {
		close(a.stop)
		<-a.done
		a.stop = nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	removeTTLFilters(a.net)
	a.attached = map[int]string{}
}

// removeTTLFilters removes our filter from every link that has it, whichever
// process attached it.
func removeTTLFilters(n *tcNetns) {
	links, err := n.nl.LinkList()
	if err != nil {
		logf("eBPF: list links on detach: %v", err)
		return
	}
	for _, l := range links {
		if !hasTTLFilter(n, l, nil) {
			continue
		}
		if err := n.nl.FilterDel(&netlink.BpfFilter{FilterAttrs: ttlFilterAttrs(l)}); err != nil {
			logf("eBPF: detach from %s: %v", l.Attrs().Name, err)
		}
	}
}
