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
				if err := Map.OpenOrCreate(); err != nil {
					return err
				}

				if err := RevMap.OpenOrCreate(); err != nil {
					Map.Close()
					return err
				}

				if err := SteerMap.OpenOrCreate(); err != nil {
					RevMap.Close()
					Map.Close()
					return err
				}

				if err := DeleteAll(); err != nil {
					SteerMap.Close()
					RevMap.Close()
					Map.Close()
					return err
				}

				if err := DeleteAllReverse(); err != nil {
					SteerMap.Close()
					RevMap.Close()
					Map.Close()
					return err
				}

				if err := DeleteAllSteer(); err != nil {
					SteerMap.Close()
					RevMap.Close()
					Map.Close()
					return err
				}

				return nil
			},

			OnStop: func(cell.HookContext) error {
				SteerMap.Close()
				RevMap.Close()
				return Map.Close()
			},
		})

		return bpf.NewMapOut(Map)
	}),
)

const (
	MapName      = "lb_egress_map"
	RevMapName   = "lb_egress_rev_map"
	SteerMapName = "lb_egress_steer_map"
	MaxEntries   = 65536
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

type RevKey struct {
	SrcIP   [4]byte  `align:"src_ip"`
	DstIP   [4]byte  `align:"dst_ip"`
	SrcPort uint16   `align:"src_port"`
	DstPort uint16   `align:"dst_port"`
	Proto   uint8    `align:"proto"`
	Pad     [3]uint8 `align:"pad"`
}

type RevValue struct {
	PodIP   [4]byte `align:"pod_ip"`
	PodPort uint16  `align:"pod_port"`
	Pad     uint16  `align:"pad"`
}

var RevMap = bpf.NewMap(
	RevMapName,
	ebpf.LRUHash,
	&RevKey{},
	&RevValue{},
	MaxEntries,
	0,
)

type SteerKey struct {
	SrcIP [4]byte `align:"src_ip"`
}

type SteerValue struct {
	LBIP    [4]byte `align:"lb_ip"`
	OwnerIP [4]byte `align:"owner_ip"`
}

var SteerMap = bpf.NewMap(
	SteerMapName,
	ebpf.LRUHash,
	&SteerKey{},
	&SteerValue{},
	MaxEntries,
	0,
)

func (k *RevKey) String() string {
	return fmt.Sprintf(
		"%s:%d -> %s:%d proto=%d",
		netip.AddrFrom4(k.SrcIP),
		k.SrcPort,
		netip.AddrFrom4(k.DstIP),
		k.DstPort,
		k.Proto,
	)
}

func (v *RevValue) String() string {
	return fmt.Sprintf(
		"pod=%s:%d",
		netip.AddrFrom4(v.PodIP),
		v.PodPort,
	)
}

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

func NewSteerKey(podIP netip.Addr) (*SteerKey, error) {
	if !podIP.Is4() {
		return nil, fmt.Errorf("pod IP must be IPv4: %s", podIP)
	}

	return &SteerKey{SrcIP: podIP.As4()}, nil
}

func NewSteerValue(lbIP, ownerIP netip.Addr) (*SteerValue, error) {
	if !lbIP.Is4() {
		return nil, fmt.Errorf("LB IP must be IPv4: %s", lbIP)
	}

	if !ownerIP.Is4() {
		return nil, fmt.Errorf("owner node IP must be IPv4: %s", ownerIP)
	}

	return &SteerValue{
		LBIP:    lbIP.As4(),
		OwnerIP: ownerIP.As4(),
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

func UpdateSteer(podIP, lbIP, ownerIP netip.Addr) error {
	key, err := NewSteerKey(podIP)
	if err != nil {
		return err
	}

	val, err := NewSteerValue(lbIP, ownerIP)
	if err != nil {
		return err
	}

	return SteerMap.Update(key, val)
}

func DeleteSteer(podIP netip.Addr) error {
	key, err := NewSteerKey(podIP)
	if err != nil {
		return err
	}

	return SteerMap.Delete(key)
}

func DeleteAllSteer() error {
	keysToDelete := make([]bpf.MapKey, 0)

	err := SteerMap.DumpWithCallback(func(key bpf.MapKey, value bpf.MapValue) {
		steerKey, ok := key.(*SteerKey)
		if !ok {
			return
		}

		keyCopy := *steerKey
		keysToDelete = append(keysToDelete, &keyCopy)
	})
	if err != nil {
		return err
	}

	for _, key := range keysToDelete {
		if err := SteerMap.Delete(key); err != nil {
			return err
		}
	}

	return nil
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

func (k *RevKey) New() bpf.MapKey {
	return &RevKey{}
}

func (k *RevKey) NewValue() bpf.MapValue {
	return &RevValue{}
}

func (k *RevKey) GetKeyPtr() unsafe.Pointer {
	return unsafe.Pointer(k)
}

func (k *RevKey) DeepCopyMapKey() bpf.MapKey {
	copy := *k
	return &copy
}

func (v *RevValue) New() bpf.MapValue {
	return &RevValue{}
}

func (v *RevValue) GetValuePtr() unsafe.Pointer {
	return unsafe.Pointer(v)
}

func (v *RevValue) DeepCopyMapValue() bpf.MapValue {
	copy := *v
	return &copy
}

func (k *SteerKey) New() bpf.MapKey {
	return &SteerKey{}
}

func (k *SteerKey) NewValue() bpf.MapValue {
	return &SteerValue{}
}

func (k *SteerKey) GetKeyPtr() unsafe.Pointer {
	return unsafe.Pointer(k)
}

func (k *SteerKey) DeepCopyMapKey() bpf.MapKey {
	keyCopy := *k
	return &keyCopy
}

func (v *SteerValue) New() bpf.MapValue {
	return &SteerValue{}
}

func (v *SteerValue) GetValuePtr() unsafe.Pointer {
	return unsafe.Pointer(v)
}

func (v *SteerValue) DeepCopyMapValue() bpf.MapValue {
	valueCopy := *v
	return &valueCopy
}

func (k *SteerKey) String() string {
	return netip.AddrFrom4(k.SrcIP).String()
}

func (v *SteerValue) String() string {
	return fmt.Sprintf(
		"lb=%s owner=%s",
		netip.AddrFrom4(v.LBIP),
		netip.AddrFrom4(v.OwnerIP),
	)
}

func DeleteReverseByPodIP(podIP netip.Addr) error {
	if !podIP.Is4() {
		return fmt.Errorf("pod IP must be IPv4: %s", podIP)
	}

	podIPBytes := podIP.As4()
	keysToDelete := make([]bpf.MapKey, 0)

	err := RevMap.DumpWithCallback(func(key bpf.MapKey, value bpf.MapValue) {
		revKey, ok := key.(*RevKey)
		if !ok {
			return
		}

		revVal, ok := value.(*RevValue)
		if !ok {
			return
		}

		if revVal.PodIP != podIPBytes {
			return
		}

		keyCopy := *revKey
		keysToDelete = append(keysToDelete, &keyCopy)
	})
	if err != nil {
		return err
	}

	for _, key := range keysToDelete {
		if err := RevMap.Delete(key); err != nil {
			return err
		}
	}

	return nil
}

func DeleteAll() error {
	keysToDelete := make([]bpf.MapKey, 0)

	err := Map.DumpWithCallback(func(key bpf.MapKey, value bpf.MapValue) {
		mapKey, ok := key.(*Key)
		if !ok {
			return
		}

		keyCopy := *mapKey
		keysToDelete = append(keysToDelete, &keyCopy)
	})
	if err != nil {
		return err
	}

	for _, key := range keysToDelete {
		if err := Map.Delete(key); err != nil {
			return err
		}
	}

	return nil
}

func DeleteAllReverse() error {
	keysToDelete := make([]bpf.MapKey, 0)

	err := RevMap.DumpWithCallback(func(key bpf.MapKey, value bpf.MapValue) {
		revKey, ok := key.(*RevKey)
		if !ok {
			return
		}

		keyCopy := *revKey
		keysToDelete = append(keysToDelete, &keyCopy)
	})
	if err != nil {
		return err
	}

	for _, key := range keysToDelete {
		if err := RevMap.Delete(key); err != nil {
			return err
		}
	}

	return nil
}
