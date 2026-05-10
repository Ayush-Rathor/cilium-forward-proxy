// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lb_egress

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/k8s/resource"
	maplbegress "github.com/cilium/cilium/pkg/maps/lbegress"
)

type mapOperations interface {
	Update(podIP, lbIP netip.Addr) error
	Delete(podIP netip.Addr) error

	UpdateSteer(podIP, lbIP, ownerIP netip.Addr) error
	DeleteSteer(podIP netip.Addr) error

	DeleteReverseByPodIP(podIP netip.Addr) error
}

type realMapOperations struct{}

func (realMapOperations) Update(podIP, lbIP netip.Addr) error {
	return maplbegress.Update(podIP, lbIP)
}

func (realMapOperations) Delete(podIP netip.Addr) error {
	return maplbegress.Delete(podIP)
}

func (realMapOperations) UpdateSteer(podIP, lbIP, ownerIP netip.Addr) error {
	return maplbegress.UpdateSteer(podIP, lbIP, ownerIP)
}

func (realMapOperations) DeleteSteer(podIP netip.Addr) error {
	return maplbegress.DeleteSteer(podIP)
}

func (realMapOperations) DeleteReverseByPodIP(podIP netip.Addr) error {
	return maplbegress.DeleteReverseByPodIP(podIP)
}

type steerEntry struct {
	LBIP    netip.Addr
	OwnerIP netip.Addr
}

type Controller struct {
	snatEntries  map[resource.Key]map[netip.Addr]netip.Addr
	steerEntries map[resource.Key]map[netip.Addr]steerEntry
	maps         mapOperations
}

func NewController() *Controller {
	return newControllerWithMapOperations(realMapOperations{})
}

func newControllerWithMapOperations(maps mapOperations) *Controller {
	return &Controller{
		snatEntries:  map[resource.Key]map[netip.Addr]netip.Addr{},
		steerEntries: map[resource.Key]map[netip.Addr]steerEntry{},
		maps:         maps,
	}
}

func (c *Controller) Reconcile(
	svcKey resource.Key,
	enabled bool,
	localNodeIsOwner bool,
	lbAddrs []netip.Addr,
	ownerNodeIP netip.Addr,
	backendIPs []netip.Addr,
) error {
	if !enabled {
		return c.CleanupService(svcKey)
	}

	lbIP, ok := singleIPv4LBIP(lbAddrs)
	if !ok {
		return c.CleanupService(svcKey)
	}

	if !ownerNodeIP.IsValid() || !ownerNodeIP.Is4() {
		return c.CleanupService(svcKey)
	}

	desiredSteer := map[netip.Addr]steerEntry{}
	desiredSNAT := map[netip.Addr]netip.Addr{}

	for _, podIP := range backendIPs {
		if !podIP.IsValid() || !podIP.Is4() {
			continue
		}

		/*
		 * Cross-node phase:
		 *
		 * Every node may hold steer entries. The bpf_lxc hook only sees
		 * traffic from local endpoints, so remote backend IPs in this map
		 * are not expected to match real local pod egress.
		 *
		 * Later hardening can filter this to local backends only.
		 */
		desiredSteer[podIP] = steerEntry{
			LBIP:    lbIP,
			OwnerIP: ownerNodeIP,
		}

		/*
		 * Only the VIP-owner node performs SNAT and owns reverse state.
		 */
		if localNodeIsOwner {
			desiredSNAT[podIP] = lbIP
		}
	}

	if err := c.reconcileSteer(svcKey, desiredSteer); err != nil {
		return err
	}

	if err := c.reconcileSNAT(svcKey, desiredSNAT); err != nil {
		return err
	}

	return nil
}

func (c *Controller) CleanupService(svcKey resource.Key) error {
	return c.cleanupService(svcKey)
}

func (c *Controller) cleanupService(svcKey resource.Key) error {
	currentSteer := c.steerEntries[svcKey]
	for podIP := range currentSteer {
		if err := c.maps.DeleteSteer(podIP); err != nil {
			return err
		}
	}
	delete(c.steerEntries, svcKey)

	currentSNAT := c.snatEntries[svcKey]
	for podIP := range currentSNAT {
		if err := c.deleteSNATPodEntries(podIP); err != nil {
			return err
		}
	}
	delete(c.snatEntries, svcKey)

	return nil
}

func (c *Controller) deleteSNATPodEntries(podIP netip.Addr) error {
	if err := c.maps.Delete(podIP); err != nil {
		return err
	}

	if err := c.maps.DeleteReverseByPodIP(podIP); err != nil {
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

func (c *Controller) reconcileSteer(
	svcKey resource.Key,
	desired map[netip.Addr]steerEntry,
) error {
	current := c.steerEntries[svcKey]
	if current == nil {
		current = map[netip.Addr]steerEntry{}
	}

	for podIP := range current {
		if _, ok := desired[podIP]; !ok {
			if err := c.maps.DeleteSteer(podIP); err != nil {
				return err
			}
			delete(current, podIP)
		}
	}

	for podIP, desiredEntry := range desired {
		if existing, ok := current[podIP]; ok &&
			existing.LBIP == desiredEntry.LBIP &&
			existing.OwnerIP == desiredEntry.OwnerIP {
			continue
		}

		if err := c.maps.UpdateSteer(podIP, desiredEntry.LBIP, desiredEntry.OwnerIP); err != nil {
			return err
		}

		current[podIP] = desiredEntry
	}

	if len(current) == 0 {
		delete(c.steerEntries, svcKey)
	} else {
		c.steerEntries[svcKey] = current
	}

	return nil
}

func (c *Controller) reconcileSNAT(
	svcKey resource.Key,
	desired map[netip.Addr]netip.Addr,
) error {
	current := c.snatEntries[svcKey]
	if current == nil {
		current = map[netip.Addr]netip.Addr{}
	}

	for podIP := range current {
		if _, ok := desired[podIP]; !ok {
			if err := c.deleteSNATPodEntries(podIP); err != nil {
				return err
			}
			delete(current, podIP)
		}
	}

	for podIP, lbIP := range desired {
		if existing, ok := current[podIP]; ok && existing == lbIP {
			continue
		}

		if err := c.maps.Update(podIP, lbIP); err != nil {
			return err
		}

		current[podIP] = lbIP
	}

	if len(current) == 0 {
		delete(c.snatEntries, svcKey)
	} else {
		c.snatEntries[svcKey] = current
	}

	return nil
}
