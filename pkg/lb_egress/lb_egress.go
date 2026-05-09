package lb_egress

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/k8s/resource"
	maplbegress "github.com/cilium/cilium/pkg/maps/lbegress"
)

type Controller struct {
	entries     map[resource.Key]map[netip.Addr]netip.Addr
	initialized bool
}

func (c *Controller) initialize() error {
	if c.initialized {
		return nil
	}

	if err := maplbegress.DeleteAll(); err != nil {
		return err
	}

	if err := maplbegress.DeleteAllReverse(); err != nil {
		return err
	}

	c.initialized = true
	return nil
}

func NewController() *Controller {
	return &Controller{
		entries: map[resource.Key]map[netip.Addr]netip.Addr{},
	}
}

func (c *Controller) Reconcile(
	svcKey resource.Key,
	enabled bool,
	currentlyLeader bool,
	lbAddrs []netip.Addr,
	backendIPs []netip.Addr,
) error {

	if err := c.initialize(); err != nil {
		return err
	}

	if !enabled || !currentlyLeader {
		return c.cleanupService(svcKey)
	}

	lbIP, ok := singleIPv4LBIP(lbAddrs)
	if !ok {
		return c.cleanupService(svcKey)
	}

	desired := map[netip.Addr]netip.Addr{}

	for _, podIP := range backendIPs {
		if !podIP.IsValid() || !podIP.Is4() {
			continue
		}

		desired[podIP] = lbIP
	}

	return c.reconcile(svcKey, desired)
}

func (c *Controller) CleanupService(svcKey resource.Key) error {
	if err := c.initialize(); err != nil {
		return err
	}

	return c.cleanupService(svcKey)
}

func (c *Controller) cleanupService(svcKey resource.Key) error {
	current := c.entries[svcKey]

	for podIP := range current {
		if err := c.deletePodEntries(podIP); err != nil {
			return err
		}
	}

	delete(c.entries, svcKey)
	return nil
}

func (c *Controller) reconcile(
	svcKey resource.Key,
	desired map[netip.Addr]netip.Addr,
) error {
	current := c.entries[svcKey]
	if current == nil {
		current = map[netip.Addr]netip.Addr{}
	}

	for podIP := range current {
		if _, ok := desired[podIP]; !ok {
			if err := c.deletePodEntries(podIP); err != nil {
				return err
			}

			delete(current, podIP)
		}
	}

	for podIP, lbIP := range desired {
		if existing, ok := current[podIP]; ok && existing == lbIP {
			continue
		}

		if err := maplbegress.Update(podIP, lbIP); err != nil {
			return err
		}

		current[podIP] = lbIP
	}

	if len(current) == 0 {
		delete(c.entries, svcKey)
	} else {
		c.entries[svcKey] = current
	}

	return nil
}

func (c *Controller) deletePodEntries(podIP netip.Addr) error {
	if err := maplbegress.Delete(podIP); err != nil {
		return err
	}

	if err := maplbegress.DeleteReverseByPodIP(podIP); err != nil {
		return err
	}

	return nil
}

func singleIPv4LBIP(addrs []netip.Addr) (netip.Addr, bool) {
	var out netip.Addr

	for _, addr := range addrs {
		if !addr.Is4() {
			continue
		}

		if out.IsValid() {
			return netip.Addr{}, false
		}

		out = addr
	}

	return out, out.IsValid()
}
