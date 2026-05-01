package lbegress

import (
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
)

var Cell = cell.Module(
	"lbegress-map",
	"LoadBalancer egress source IP BPF map",

	cell.Provide(func(lc cell.Lifecycle) bpf.MapOut[*bpf.Map] {
		lc.Append(cell.Hook{
			OnStart: func(cell.HookContext) error {
				return Map.OpenOrCreate()
			},
			OnStop: func(cell.HookContext) error {
				return Map.Close()
			},
		})

		return bpf.NewMapOut(Map)
	}),
)

const (
	MapName    = "lb_egress_map"
	MaxEntries = 65536
)

type Key struct {
	SrcIP [4]byte `align:"src_ip"`
}

type Value struct {
	LBIP [4]byte `align:"lb_ip"`
}

var Map = bpf.NewMap(
	MapName,
	ebpf.LRUHash,
	&Key{},
	&Value{},
	MaxEntries,
	0,
)

func NewKey(podIP netip.Addr) (*Key, error) {
	if !podIP.Is4() {
		return nil, fmt.Errorf("pod IP must be IPv4: %s", podIP)
	}

	return &Key{
		SrcIP: podIP.As4(),
	}, nil
}

func NewValue(lbIP netip.Addr) (*Value, error) {
	if !lbIP.Is4() {
		return nil, fmt.Errorf("LB IP must be IPv4: %s", lbIP)
	}

	return &Value{
		LBIP: lbIP.As4(),
	}, nil
}

func Update(podIP, lbIP netip.Addr) error {
	key, err := NewKey(podIP)
	if err != nil {
		return err
	}

	val, err := NewValue(lbIP)
	if err != nil {
		return err
	}

	return Map.Update(key, val)
}

func Delete(podIP netip.Addr) error {
	key, err := NewKey(podIP)
	if err != nil {
		return err
	}

	return Map.Delete(key)
}

func (k *Key) String() string {
	return netip.AddrFrom4(k.SrcIP).String()
}

func (k *Key) GetKeyPtr() unsafe.Pointer {
	return unsafe.Pointer(k)
}

func (k *Key) New() bpf.MapKey {
	return &Key{}
}

func (k *Key) NewValue() bpf.MapValue {
	return &Value{}
}

func (k *Key) DeepCopyMapKey() bpf.MapKey {
	copy := *k
	return &copy
}

func (v *Value) String() string {
	return netip.AddrFrom4(v.LBIP).String()
}

func (v *Value) GetValuePtr() unsafe.Pointer {
	return unsafe.Pointer(v)
}

func (v *Value) New() bpf.MapValue {
	return &Value{}
}

func (v *Value) DeepCopyMapValue() bpf.MapValue {
	copy := *v
	return &copy
}
