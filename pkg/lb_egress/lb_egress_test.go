// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lb_egress

import (
	"net/netip"
	"testing"

	"github.com/cilium/cilium/pkg/k8s/resource"
)

type fakeMapOperations struct {
	entries           map[netip.Addr]netip.Addr
	deleted           []netip.Addr
	reverseDeleted    []netip.Addr
	updateCallCounter int
}

func newFakeMapOperations() *fakeMapOperations {
	return &fakeMapOperations{
		entries: map[netip.Addr]netip.Addr{},
	}
}

func (f *fakeMapOperations) Update(podIP, lbIP netip.Addr) error {
	f.entries[podIP] = lbIP
	f.updateCallCounter++
	return nil
}

func (f *fakeMapOperations) Delete(podIP netip.Addr) error {
	delete(f.entries, podIP)
	f.deleted = append(f.deleted, podIP)
	return nil
}

func (f *fakeMapOperations) DeleteReverseByPodIP(podIP netip.Addr) error {
	f.reverseDeleted = append(f.reverseDeleted, podIP)
	return nil
}

func TestReconcileProgramsDesiredPodEntries(t *testing.T) {
	maps := newFakeMapOperations()
	controller := newControllerWithMapOperations(maps)

	svcKey := resource.Key{Namespace: "default", Name: "svc"}
	podIP := netip.MustParseAddr("10.233.82.152")
	lbIP := netip.MustParseAddr("10.20.32.240")

	err := controller.Reconcile(
		svcKey,
		true,
		true,
		[]netip.Addr{lbIP},
		[]netip.Addr{podIP},
	)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	if got := maps.entries[podIP]; got != lbIP {
		t.Fatalf("expected pod %s to map to LB IP %s, got %s", podIP, lbIP, got)
	}
}

func TestReconcileDeletesStalePodAndReverseEntries(t *testing.T) {
	maps := newFakeMapOperations()
	controller := newControllerWithMapOperations(maps)

	svcKey := resource.Key{Namespace: "default", Name: "svc"}
	oldPodIP := netip.MustParseAddr("10.233.82.152")
	newPodIP := netip.MustParseAddr("10.233.82.166")
	lbIP := netip.MustParseAddr("10.20.32.240")

	err := controller.Reconcile(
		svcKey,
		true,
		true,
		[]netip.Addr{lbIP},
		[]netip.Addr{oldPodIP, newPodIP},
	)
	if err != nil {
		t.Fatalf("initial reconcile failed: %v", err)
	}

	err = controller.Reconcile(
		svcKey,
		true,
		true,
		[]netip.Addr{lbIP},
		[]netip.Addr{newPodIP},
	)
	if err != nil {
		t.Fatalf("second reconcile failed: %v", err)
	}

	if _, ok := maps.entries[oldPodIP]; ok {
		t.Fatalf("old pod IP %s still exists in map", oldPodIP)
	}

	if got := maps.entries[newPodIP]; got != lbIP {
		t.Fatalf("expected new pod IP %s to remain mapped to %s, got %s", newPodIP, lbIP, got)
	}

	assertContainsAddr(t, maps.deleted, oldPodIP)
	assertContainsAddr(t, maps.reverseDeleted, oldPodIP)
}

func TestCleanupServiceIsScopedToOneService(t *testing.T) {
	maps := newFakeMapOperations()
	controller := newControllerWithMapOperations(maps)

	svc1 := resource.Key{Namespace: "default", Name: "svc1"}
	svc2 := resource.Key{Namespace: "default", Name: "svc2"}

	pod1 := netip.MustParseAddr("10.233.82.152")
	pod2 := netip.MustParseAddr("10.233.82.166")

	lb1 := netip.MustParseAddr("10.20.32.240")
	lb2 := netip.MustParseAddr("10.20.32.241")

	if err := controller.Reconcile(svc1, true, true, []netip.Addr{lb1}, []netip.Addr{pod1}); err != nil {
		t.Fatalf("reconcile svc1 failed: %v", err)
	}

	if err := controller.Reconcile(svc2, true, true, []netip.Addr{lb2}, []netip.Addr{pod2}); err != nil {
		t.Fatalf("reconcile svc2 failed: %v", err)
	}

	if err := controller.CleanupService(svc2); err != nil {
		t.Fatalf("cleanup svc2 failed: %v", err)
	}

	if got := maps.entries[pod1]; got != lb1 {
		t.Fatalf("svc1 pod mapping was incorrectly removed, got %s", got)
	}

	if _, ok := maps.entries[pod2]; ok {
		t.Fatalf("svc2 pod mapping still exists after cleanup")
	}

	assertContainsAddr(t, maps.deleted, pod2)
	assertContainsAddr(t, maps.reverseDeleted, pod2)
	assertNotContainsAddr(t, maps.deleted, pod1)
	assertNotContainsAddr(t, maps.reverseDeleted, pod1)
}

func TestReconcileCleansUpWhenDisabledOrNotLeader(t *testing.T) {
	maps := newFakeMapOperations()
	controller := newControllerWithMapOperations(maps)

	svcKey := resource.Key{Namespace: "default", Name: "svc"}
	podIP := netip.MustParseAddr("10.233.82.152")
	lbIP := netip.MustParseAddr("10.20.32.240")

	if err := controller.Reconcile(svcKey, true, true, []netip.Addr{lbIP}, []netip.Addr{podIP}); err != nil {
		t.Fatalf("initial reconcile failed: %v", err)
	}

	if err := controller.Reconcile(svcKey, false, true, []netip.Addr{lbIP}, []netip.Addr{podIP}); err != nil {
		t.Fatalf("disabled reconcile failed: %v", err)
	}

	if _, ok := maps.entries[podIP]; ok {
		t.Fatalf("pod mapping still exists after feature disabled")
	}

	assertContainsAddr(t, maps.deleted, podIP)
	assertContainsAddr(t, maps.reverseDeleted, podIP)
}

func TestSingleIPv4LBIP(t *testing.T) {
	ipv4 := netip.MustParseAddr("10.20.32.240")
	otherIPv4 := netip.MustParseAddr("10.20.32.241")
	ipv6 := netip.MustParseAddr("fd00::1")

	got, ok := singleIPv4LBIP([]netip.Addr{ipv4})
	if !ok || got != ipv4 {
		t.Fatalf("expected single IPv4 %s, got %s ok=%v", ipv4, got, ok)
	}

	got, ok = singleIPv4LBIP([]netip.Addr{ipv6, ipv4})
	if !ok || got != ipv4 {
		t.Fatalf("expected IPv6 to be ignored and IPv4 %s selected, got %s ok=%v", ipv4, got, ok)
	}

	_, ok = singleIPv4LBIP([]netip.Addr{ipv4, otherIPv4})
	if ok {
		t.Fatalf("expected multiple IPv4 LB IPs to be rejected")
	}

	_, ok = singleIPv4LBIP([]netip.Addr{ipv6})
	if ok {
		t.Fatalf("expected no IPv4 LB IP to be rejected")
	}
}

func assertContainsAddr(t *testing.T, addrs []netip.Addr, expected netip.Addr) {
	t.Helper()

	for _, addr := range addrs {
		if addr == expected {
			return
		}
	}

	t.Fatalf("expected %s in %v", expected, addrs)
}

func assertNotContainsAddr(t *testing.T, addrs []netip.Addr, unexpected netip.Addr) {
	t.Helper()

	for _, addr := range addrs {
		if addr == unexpected {
			t.Fatalf("did not expect %s in %v", unexpected, addrs)
		}
	}
}
