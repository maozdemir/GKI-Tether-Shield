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

// tcAttacher keeps our program attached to the egress of every upstream
// interface that is up.
type tcAttacher struct {
	progs *ttlProgSet
	ids   map[int]bool // kernel IDs of our loaded programs

	mu       sync.Mutex
	attached map[int]string // ifindex -> name
	stop     chan struct{}
	done     chan struct{}
}

func newTCAttacher(progs *ttlProgSet) *tcAttacher {
	ids := map[int]bool{}
	for _, p := range []*ebpf.Program{progs.raw, progs.eth} {
		if info, err := p.Info(); err == nil {
			if id, ok := info.ID(); ok {
				ids[int(id)] = true
			}
		}
	}
	return &tcAttacher{progs: progs, ids: ids, attached: map[int]string{}}
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
	subscribed := netlink.LinkSubscribe(updates, a.stop) == nil
	if !subscribed {
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
	links, err := netlink.LinkList()
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
		if a.hasFilter(l, true) {
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

// hasFilter reports whether our filter is on l's egress hook. With current
// set, it must also run one of the programs this process loaded (a filter
// left by an earlier daemon uses its old maps, so it gets replaced).
func (a *tcAttacher) hasFilter(l netlink.Link, current bool) bool {
	filters, err := netlink.FilterList(l, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return false
	}
	want := netlink.MakeHandle(0, ttlFilterHandle)
	for _, f := range filters {
		bf, ok := f.(*netlink.BpfFilter)
		if !ok || f.Attrs().Handle != want || !strings.HasPrefix(bf.Name, ttlFilterName) {
			continue
		}
		if !current || a.ids[bf.Id] {
			return true
		}
	}
	return false
}

// attach adds a clsact qdisc if the link has none (never replacing an
// existing one, which would drop netd's filters) and installs our filter.
func (a *tcAttacher) attach(l netlink.Link) error {
	if err := ensureClsact(l); err != nil {
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
	if err := netlink.FilterReplace(f); err != nil {
		return fmt.Errorf("add tc filter: %w", err)
	}
	return nil
}

func ensureClsact(l netlink.Link) error {
	qdiscs, err := netlink.QdiscList(l)
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
	if err := netlink.QdiscAdd(q); err != nil && !errors.Is(err, unix.EEXIST) {
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
	links, err := netlink.LinkList()
	if err != nil {
		logf("eBPF: list links on detach: %v", err)
		return
	}
	for _, l := range links {
		if !a.hasFilter(l, false) {
			continue
		}
		if err := netlink.FilterDel(&netlink.BpfFilter{FilterAttrs: ttlFilterAttrs(l)}); err != nil {
			logf("eBPF: detach from %s: %v", l.Attrs().Name, err)
		}
	}
	a.attached = map[int]string{}
}
