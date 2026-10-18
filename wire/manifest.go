package wire

import (
	"bytes"
	"sort"
)

type Architecture uint8

const (
	AMD64 Architecture = 1
	ARM64 Architecture = 2
)

type Personality uint8

const (
	Native Personality = 1
	BSD    Personality = 2
	Linux  Personality = 3
)

type Kind uint8

const (
	Directory Kind = 1
	Data      Kind = 2
	Image     Kind = 3
)

type Publisher struct {
	RootKeyID       [DigestSize]byte
	LeafKeyID       [DigestSize]byte
	DelegationEpoch uint64
	RevocationEpoch uint64
}

type NativeABI struct {
	Epoch            uint32
	Features         uint64
	MinKernelBuildID uint64
}

type EntryPoint struct {
	Architecture Architecture
	ImagePath    string
	Personality  Personality
	ABI          *NativeABI
}

type Entry struct {
	Path   string
	Kind   Kind
	Mode   uint16
	Size   uint64
	Digest [DigestSize]byte
}

type StatePolicy struct {
	Current         uint32
	MinimumReadable uint32
	MaximumReadable uint32
}

type HealthPolicy struct {
	Enabled   bool
	ImagePath string
	TimeoutMS uint32
}

type Extension struct {
	ID    uint32
	Value []byte
}

type Manifest struct {
	ApplicationID       string
	DisplayName         string
	ReleaseVersion      string
	ReleaseSequence     uint64
	PayloadDigest       [DigestSize]byte
	Publisher           Publisher
	EntryPoints         []EntryPoint
	Inventory           []Entry
	Resources           []string
	Icons               []string
	Grants              []string
	Portals             []string
	State               StatePolicy
	Health              HealthPolicy
	Extensions          []Extension
	PublisherIdentity   [DigestSize]byte
	ApplicationIdentity [DigestSize]byte
	ReleaseID           [DigestSize]byte
}

var emptySHA256 = [DigestSize]byte{
	0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
	0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
	0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
	0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
}

func Decode(data []byte) (*Manifest, error) {
	if len(data) > ManifestMax {
		return nil, &Error{ResourceLimit}
	}
	if f := preflight(data); f != OK {
		return nil, &Error{f}
	}
	p := &parser{data: data}
	m := &Manifest{}
	if !p.manifest(m) || !p.relations(m) || !p.finish(m) {
		if p.failure == OK {
			p.failure = Internal
		}
		return nil, &Error{p.failure}
	}
	return m, nil
}

func (p *parser) manifest(m *Manifest) bool {
	count, ok := p.container(majorMap, 1)
	if !ok {
		return false
	}
	if count < 16 {
		return p.fail(RequiredField)
	}
	var order keyOrder
	var seen uint32
	for i := uint64(0); i < count; i++ {
		key, ok := p.mapKey(&order)
		if !ok {
			return false
		}
		if key < 1 || key > 16 {
			return p.fail(UnknownField)
		}
		seen |= 1 << (key - 1)
		if !p.manifestField(m, key) {
			return false
		}
	}
	if seen != 0xffff {
		return p.fail(RequiredField)
	}
	if p.offset != len(p.data) {
		return p.fail(CBORTrailing)
	}
	return true
}

func (p *parser) manifestField(m *Manifest, key uint64) bool {
	var ok bool
	switch key {
	case 1:
		var version uint64
		if version, ok = p.uint(); !ok {
			return false
		}
		if version != 1 {
			return p.fail(IntegerRange)
		}
	case 2:
		if m.ApplicationID, ok = p.text(); !ok {
			return false
		}
		if len(m.ApplicationID) == 0 || len(m.ApplicationID) > ApplicationIDMax {
			return p.fail(StringSize)
		}
		if !validApplicationID(m.ApplicationID) {
			return p.fail(ApplicationID)
		}
	case 3:
		if m.DisplayName, ok = p.text(); !ok {
			return false
		}
		if len(m.DisplayName) == 0 || len(m.DisplayName) > 255 {
			return p.fail(StringSize)
		}
	case 4:
		if m.ReleaseVersion, ok = p.text(); !ok {
			return false
		}
		if len(m.ReleaseVersion) == 0 || len(m.ReleaseVersion) > 128 {
			return p.fail(StringSize)
		}
	case 5:
		if m.ReleaseSequence, ok = p.uint(); !ok {
			return false
		}
		if m.ReleaseSequence == 0 {
			return p.fail(IntegerRange)
		}
	case 6:
		var digest []byte
		if digest, ok = p.bytes(); !ok {
			return false
		}
		if len(digest) != DigestSize {
			return p.fail(InvalidDigestSize)
		}
		copy(m.PayloadDigest[:], digest)
	case 7:
		return p.publisher(&m.Publisher)
	case 8:
		return p.entryPoints(m)
	case 9:
		return p.inventory(m)
	case 10:
		m.Resources, ok = p.strings(resourcesMax, true)
		return ok
	case 11:
		m.Icons, ok = p.strings(iconsMax, true)
		return ok
	case 12:
		m.Grants, ok = p.strings(grantsMax, false)
		return ok
	case 13:
		m.Portals, ok = p.strings(portalsMax, false)
		return ok
	case 14:
		return p.statePolicy(&m.State)
	case 15:
		return p.healthPolicy(&m.Health)
	case 16:
		return p.extensions(m)
	}
	return true
}

func validApplicationID(id string) bool {
	if len(id) == 0 || len(id) > ApplicationIDMax {
		return false
	}
	for i := 0; i < len(id); i++ {
		b := id[i]
		if (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') {
			continue
		}
		if (b == '.' || b == '-') && i != 0 && i+1 != len(id) {
			continue
		}
		return false
	}
	return true
}

func validName(name string) bool {
	if len(name) == 0 || len(name) > 128 || name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for i := 1; i < len(name); i++ {
		b := name[i]
		if (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '.' || b == '-' {
			continue
		}
		return false
	}
	return true
}

func ValidPath(path string) bool {
	if len(path) == 0 || len(path) > PathMax || path[0] == '/' || path[len(path)-1] == '/' {
		return false
	}
	component := 0
	for i := 0; i <= len(path); i++ {
		if i == len(path) || path[i] == '/' {
			if component == 0 || component > pathComponentMax {
				return false
			}
			name := path[i-component : i]
			if name == "." || name == ".." || (len(name) >= 5 && name[:5] == ".six-") {
				return false
			}
			component = 0
			continue
		}
		b := path[i]
		if !((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') ||
			b == '.' || b == '_' || b == '+' || b == '-') {
			return false
		}
		component++
	}
	return true
}

func (p *parser) publisher(out *Publisher) bool {
	count, ok := p.container(majorMap, 2)
	if !ok {
		return false
	}
	var order keyOrder
	var seen uint32
	for i := uint64(0); i < count; i++ {
		key, ok := p.mapKey(&order)
		if !ok {
			return false
		}
		if key < 1 || key > 4 {
			return p.fail(UnknownField)
		}
		seen |= 1 << (key - 1)
		if key == 1 || key == 2 {
			digest, ok := p.bytes()
			if !ok {
				return false
			}
			if len(digest) != DigestSize {
				return p.fail(InvalidDigestSize)
			}
			if key == 1 {
				copy(out.RootKeyID[:], digest)
			} else {
				copy(out.LeafKeyID[:], digest)
			}
			continue
		}
		value, ok := p.uint()
		if !ok {
			return false
		}
		if key == 3 {
			out.DelegationEpoch = value
		} else {
			out.RevocationEpoch = value
		}
	}
	if seen != 0x0f {
		return p.fail(RequiredField)
	}
	return true
}

func (p *parser) abi(depth int, personality Personality) (*NativeABI, bool) {
	count, ok := p.container(majorMap, depth)
	if !ok {
		return nil, false
	}
	if personality != Native {
		if count != 0 {
			return nil, p.fail(EntryABI)
		}
		return nil, true
	}
	if count != 3 {
		return nil, p.fail(EntryABI)
	}
	abi := &NativeABI{}
	var order keyOrder
	var seen uint32
	for i := uint64(0); i < count; i++ {
		key, ok := p.mapKey(&order)
		if !ok {
			return nil, false
		}
		if key < 1 || key > 3 {
			return nil, p.fail(UnknownField)
		}
		seen |= 1 << (key - 1)
		value, ok := p.uint()
		if !ok {
			return nil, false
		}
		switch key {
		case 1:
			if value == 0 || value > 0xffffffff {
				return nil, p.fail(IntegerRange)
			}
			abi.Epoch = uint32(value)
		case 2:
			abi.Features = value
		case 3:
			abi.MinKernelBuildID = value
		}
	}
	if seen != 0x07 {
		return nil, p.fail(EntryABI)
	}
	return abi, true
}

func (p *parser) entryPoint(depth int, entry *EntryPoint) bool {
	count, ok := p.container(majorMap, depth)
	if !ok {
		return false
	}
	var order keyOrder
	var seen uint32
	for i := uint64(0); i < count; i++ {
		key, ok := p.mapKey(&order)
		if !ok {
			return false
		}
		if key < 1 || key > 4 {
			return p.fail(UnknownField)
		}
		seen |= 1 << (key - 1)
		switch key {
		case 1:
			value, ok := p.uint()
			if !ok {
				return false
			}
			if value < 1 || value > 2 {
				return p.fail(EntryArchitecture)
			}
			entry.Architecture = Architecture(value)
		case 2:
			if entry.ImagePath, ok = p.text(); !ok {
				return false
			}
			if !ValidPath(entry.ImagePath) {
				return p.fail(InvalidPath)
			}
		case 3:
			value, ok := p.uint()
			if !ok {
				return false
			}
			if value < 1 || value > 3 {
				return p.fail(EntryABI)
			}
			entry.Personality = Personality(value)
		case 4:
			if seen&(1<<2) == 0 {
				return p.fail(CBOROrder)
			}
			if entry.ABI, ok = p.abi(depth+1, entry.Personality); !ok {
				return false
			}
		}
	}
	if seen != 0x0f {
		return p.fail(RequiredField)
	}
	return true
}

func (p *parser) entryPoints(m *Manifest) bool {
	count, ok := p.container(majorArray, 2)
	if !ok {
		return false
	}
	if count == 0 || count > entryPointsMax {
		return p.fail(ResourceLimit)
	}
	m.EntryPoints = make([]EntryPoint, count)
	for i := range m.EntryPoints {
		if !p.entryPoint(3, &m.EntryPoints[i]) {
			return false
		}
	}
	return true
}

func (p *parser) inventoryItem(depth int, entry *Entry) bool {
	count, ok := p.container(majorMap, depth)
	if !ok {
		return false
	}
	var order keyOrder
	var seen uint32
	var kind, mode uint64
	for i := uint64(0); i < count; i++ {
		key, ok := p.mapKey(&order)
		if !ok {
			return false
		}
		if key < 1 || key > 5 {
			return p.fail(UnknownField)
		}
		seen |= 1 << (key - 1)
		switch key {
		case 1:
			if entry.Path, ok = p.text(); !ok {
				return false
			}
			if !ValidPath(entry.Path) {
				return p.fail(InvalidPath)
			}
			if entry.Path == "SXI" || (len(entry.Path) > 3 && entry.Path[:4] == "SXI/") {
				return p.fail(ControlSubtree)
			}
		case 2:
			if kind, ok = p.uint(); !ok {
				return false
			}
			if kind < 1 || kind > 3 {
				return p.fail(InventoryKind)
			}
		case 3:
			if mode, ok = p.uint(); !ok {
				return false
			}
		case 4:
			if entry.Size, ok = p.uint(); !ok {
				return false
			}
		case 5:
			digest, ok := p.bytes()
			if !ok {
				return false
			}
			if len(digest) != DigestSize {
				return p.fail(InventoryDigest)
			}
			copy(entry.Digest[:], digest)
		}
	}
	if seen != 0x1f {
		return p.fail(RequiredField)
	}
	if (kind == 1 && mode != 0o555) || (kind == 2 && mode != 0o444) || (kind == 3 && mode != 0o555) {
		return p.fail(InventoryMode)
	}
	if kind == 1 && entry.Size != 0 {
		return p.fail(InventorySize)
	}
	if kind == 1 && entry.Digest != emptySHA256 {
		return p.fail(InventoryDigest)
	}
	entry.Kind = Kind(kind)
	entry.Mode = uint16(mode)
	return true
}

func (p *parser) inventory(m *Manifest) bool {
	count, ok := p.container(majorArray, 2)
	if !ok {
		return false
	}
	if count == 0 || count > InventoryMax {
		return p.fail(ResourceLimit)
	}
	m.Inventory = make([]Entry, count)
	for i := range m.Inventory {
		if !p.inventoryItem(3, &m.Inventory[i]) {
			return false
		}
	}
	return true
}

func (p *parser) strings(limit uint64, paths bool) ([]string, bool) {
	count, ok := p.container(majorArray, 2)
	if !ok {
		return nil, false
	}
	if count > limit {
		return nil, p.fail(ResourceLimit)
	}
	values := make([]string, count)
	for i := range values {
		value, ok := p.text()
		if !ok {
			return nil, false
		}
		if paths {
			if !ValidPath(value) {
				return nil, p.fail(InvalidPath)
			}
		} else if !validName(value) {
			return nil, p.fail(InvalidName)
		}
		values[i] = value
	}
	return values, true
}

func (p *parser) statePolicy(out *StatePolicy) bool {
	count, ok := p.container(majorMap, 2)
	if !ok {
		return false
	}
	var order keyOrder
	var seen uint32
	for i := uint64(0); i < count; i++ {
		key, ok := p.mapKey(&order)
		if !ok {
			return false
		}
		if key < 1 || key > 3 {
			return p.fail(UnknownField)
		}
		value, ok := p.uint()
		if !ok {
			return false
		}
		if value > 0xffffffff {
			return p.fail(IntegerRange)
		}
		seen |= 1 << (key - 1)
		switch key {
		case 1:
			out.Current = uint32(value)
		case 2:
			out.MinimumReadable = uint32(value)
		case 3:
			out.MaximumReadable = uint32(value)
		}
	}
	if seen != 0x07 {
		return p.fail(RequiredField)
	}
	if out.MinimumReadable > out.Current || out.Current > out.MaximumReadable {
		return p.fail(InvalidStatePolicy)
	}
	return true
}

func (p *parser) healthPolicy(out *HealthPolicy) bool {
	count, ok := p.container(majorMap, 2)
	if !ok {
		return false
	}
	var order keyOrder
	var seen uint32
	var mode, timeout uint64
	for i := uint64(0); i < count; i++ {
		key, ok := p.mapKey(&order)
		if !ok {
			return false
		}
		if key < 1 || key > 3 {
			return p.fail(UnknownField)
		}
		seen |= 1 << (key - 1)
		switch key {
		case 1:
			if mode, ok = p.uint(); !ok {
				return false
			}
		case 2:
			if out.ImagePath, ok = p.text(); !ok {
				return false
			}
			if !ValidPath(out.ImagePath) {
				return p.fail(InvalidPath)
			}
		case 3:
			if timeout, ok = p.uint(); !ok {
				return false
			}
		}
	}
	if seen&0x01 == 0 || mode > 1 {
		return p.fail(InvalidHealthPolicy)
	}
	if mode == 0 {
		if seen != 0x01 {
			return p.fail(InvalidHealthPolicy)
		}
		return true
	}
	if seen != 0x07 || timeout == 0 || timeout > 300000 {
		return p.fail(InvalidHealthPolicy)
	}
	out.Enabled = true
	out.TimeoutMS = uint32(timeout)
	return true
}

func (p *parser) recordFailure() bool {
	if p.failure == CBORType {
		p.failure = ExtensionRecord
	}
	return false
}

func (p *parser) extensions(m *Manifest) bool {
	count, ok := p.container(majorMap, 2)
	if !ok {
		return false
	}
	if count > extensionsMax {
		return p.fail(ResourceLimit)
	}
	var order keyOrder
	for i := uint64(0); i < count; i++ {
		id, ok := p.mapKey(&order)
		if !ok {
			return false
		}
		if id == 0 || id > 0xffffffff {
			return p.fail(ExtensionID)
		}
		items, ok := p.container(majorArray, 3)
		if !ok {
			return p.recordFailure()
		}
		if items != 2 {
			return p.fail(ExtensionRecord)
		}
		critical, ok := p.boolean()
		if !ok {
			return p.recordFailure()
		}
		value, ok := p.bytes()
		if !ok {
			return p.recordFailure()
		}
		if len(value) > extensionBytesMax {
			return p.fail(ResourceLimit)
		}
		if critical {
			return p.fail(CriticalExtension)
		}
		m.Extensions = append(m.Extensions, Extension{ID: uint32(id), Value: append([]byte(nil), value...)})
	}
	return true
}

func (m *Manifest) Find(path string) *Entry {
	i := sort.Search(len(m.Inventory), func(i int) bool { return m.Inventory[i].Path >= path })
	if i < len(m.Inventory) && m.Inventory[i].Path == path {
		return &m.Inventory[i]
	}
	return nil
}

func foldASCII(s string) []byte {
	out := []byte(s)
	for i, b := range out {
		if b >= 'A' && b <= 'Z' {
			out[i] = b + ('a' - 'A')
		}
	}
	return out
}

func (p *parser) stringOrder(values []string) bool {
	for i := 1; i < len(values); i++ {
		switch c := bytes.Compare([]byte(values[i-1]), []byte(values[i])); {
		case c == 0:
			return p.fail(DuplicatePath)
		case c > 0:
			return p.fail(InventoryOrder)
		}
	}
	return true
}

func (p *parser) relations(m *Manifest) bool {
	for i := 1; i < len(m.EntryPoints); i++ {
		previous, current := m.EntryPoints[i-1].Architecture, m.EntryPoints[i].Architecture
		if current == previous {
			return p.fail(EntryArchitecture)
		}
		if current < previous {
			return p.fail(EntryOrder)
		}
	}
	for i := 1; i < len(m.Inventory); i++ {
		switch c := bytes.Compare([]byte(m.Inventory[i-1].Path), []byte(m.Inventory[i].Path)); {
		case c == 0:
			return p.fail(DuplicatePath)
		case c > 0:
			return p.fail(InventoryOrder)
		}
	}
	if !p.stringOrder(m.Resources) || !p.stringOrder(m.Icons) ||
		!p.stringOrder(m.Grants) || !p.stringOrder(m.Portals) {
		return false
	}
	folded := make([][]byte, len(m.Inventory))
	for i := range m.Inventory {
		folded[i] = foldASCII(m.Inventory[i].Path)
	}
	sort.Slice(folded, func(a, b int) bool { return bytes.Compare(folded[a], folded[b]) < 0 })
	for i := 1; i < len(folded); i++ {
		if bytes.Equal(folded[i-1], folded[i]) {
			return p.fail(CaseCollision)
		}
	}
	for _, entry := range m.Inventory {
		slash := bytes.LastIndexByte([]byte(entry.Path), '/')
		if slash < 0 {
			continue
		}
		parent := m.Find(entry.Path[:slash])
		if parent == nil || parent.Kind != Directory {
			return p.fail(InventoryParent)
		}
	}
	for _, list := range [][]string{m.Resources, m.Icons} {
		for _, path := range list {
			if m.Find(path) == nil {
				return p.fail(InventoryParent)
			}
		}
	}
	for _, entry := range m.EntryPoints {
		if target := m.Find(entry.ImagePath); target == nil || target.Kind != Image {
			return p.fail(EntryKind)
		}
	}
	if m.Health.Enabled {
		if target := m.Find(m.Health.ImagePath); target == nil || target.Kind != Image {
			return p.fail(InvalidHealthPolicy)
		}
	}
	return true
}

func (p *parser) finish(m *Manifest) bool {
	if PayloadDigestOf(m.Inventory) != m.PayloadDigest {
		return p.fail(PayloadDigest)
	}
	m.PublisherIdentity = PublisherIdentity(m.Publisher.RootKeyID)
	m.ApplicationIdentity = ApplicationIdentity(m.PublisherIdentity, m.ApplicationID)
	m.ReleaseID = ReleaseID(p.data)
	return true
}
