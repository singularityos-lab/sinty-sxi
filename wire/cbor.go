package wire

import "bytes"

const (
	ManifestMax       = 262144
	DigestSize        = 32
	ApplicationIDMax  = 255
	PathMax           = 1024
	InventoryMax      = 4096
	depthMax          = 8
	entryPointsMax    = 16
	resourcesMax      = 256
	iconsMax          = 64
	grantsMax         = 128
	portalsMax        = 64
	extensionsMax     = 32
	extensionBytesMax = 4096
	decodedStringsMax = 1048576
	pathComponentMax  = 255
)

const (
	majorUnsigned = 0
	majorNegative = 1
	majorBytes    = 2
	majorText     = 3
	majorArray    = 4
	majorMap      = 5
	majorTag      = 6
	majorSimple   = 7
	majorNone     = 0xff
)

type parser struct {
	data    []byte
	offset  int
	decoded int
	failure Failure
}

func (p *parser) fail(f Failure) bool {
	if p.failure == OK {
		p.failure = f
	}
	return false
}

type scan int

const (
	scanOK scan = iota
	scanTruncated
	scanInvalid
)

func (p *parser) argument(truncated func() bool) (major uint8, value uint64, ok bool) {
	if p.offset >= len(p.data) {
		return 0, 0, truncated()
	}
	initial := p.data[p.offset]
	p.offset++
	major = initial >> 5
	additional := initial & 0x1f
	if additional < 24 {
		return major, uint64(additional), true
	}
	if additional == 31 {
		return major, 0, p.fail(CBORIndefinite)
	}
	if additional > 27 {
		return major, 0, p.fail(CBORType)
	}
	size := 1 << (additional - 24)
	if size > len(p.data)-p.offset {
		return major, 0, truncated()
	}
	for i := 0; i < size; i++ {
		value = value<<8 | uint64(p.data[p.offset])
		p.offset++
	}
	if !(major == majorSimple && additional >= 25) &&
		((size == 1 && value < 24) ||
			(size == 2 && value <= 0xff) ||
			(size == 4 && value <= 0xffff) ||
			(size == 8 && value <= 0xffffffff)) {
		return major, 0, p.fail(CBORShortest)
	}
	return major, value, true
}

func (p *parser) read() (uint8, uint64, bool) {
	return p.argument(func() bool { return p.fail(CBORType) })
}

func (p *parser) container(wanted uint8, depth int) (uint64, bool) {
	major, count, ok := p.read()
	if !ok {
		return 0, false
	}
	if major == majorTag {
		return 0, p.fail(CBORTag)
	}
	if major != wanted {
		return 0, p.fail(CBORType)
	}
	if depth > depthMax {
		return 0, p.fail(ResourceLimit)
	}
	return count, true
}

func (p *parser) uint() (uint64, bool) {
	major, value, ok := p.read()
	if !ok {
		return 0, false
	}
	if major == majorTag {
		return 0, p.fail(CBORTag)
	}
	if major != majorUnsigned {
		return 0, p.fail(CBORType)
	}
	return value, true
}

func (p *parser) boolean() (bool, bool) {
	major, value, ok := p.read()
	if !ok {
		return false, false
	}
	if major != majorSimple || (value != 20 && value != 21) {
		return false, p.fail(CBORType)
	}
	return value == 21, true
}

func (p *parser) stringBytes(wanted uint8) ([]byte, bool) {
	major, length, ok := p.read()
	if !ok {
		return nil, false
	}
	if major == majorTag {
		return nil, p.fail(CBORTag)
	}
	if major != wanted {
		return nil, p.fail(CBORType)
	}
	if length > uint64(len(p.data)-p.offset) {
		return nil, p.fail(CBORType)
	}
	if length > uint64(decodedStringsMax-p.decoded) {
		return nil, p.fail(ResourceLimit)
	}
	p.decoded += int(length)
	value := p.data[p.offset : p.offset+int(length)]
	p.offset += int(length)
	return value, true
}

func (p *parser) text() (string, bool) {
	value, ok := p.stringBytes(majorText)
	if !ok {
		return "", false
	}
	if f := checkText(value); f != OK {
		return "", p.fail(f)
	}
	return string(value), true
}

func (p *parser) bytes() ([]byte, bool) {
	return p.stringBytes(majorBytes)
}

func checkText(value []byte) Failure {
	ascii, valid := validUTF8(value)
	if !valid {
		return InvalidUTF8
	}
	if !ascii && !isNFC(value) {
		return TextNFC
	}
	return OK
}

type keyOrder struct {
	previous []byte
	have     bool
}

func (k *keyOrder) next(encoded []byte) Failure {
	if k.have {
		switch bytes.Compare(k.previous, encoded) {
		case 0:
			return CBORDuplicateKey
		case 1:
			return CBOROrder
		}
	}
	k.previous = append(k.previous[:0], encoded...)
	k.have = true
	return OK
}

func (p *parser) mapKey(order *keyOrder) (uint64, bool) {
	start := p.offset
	major, key, ok := p.read()
	if !ok {
		return 0, false
	}
	if major == majorTag {
		return 0, p.fail(CBORTag)
	}
	if major != majorUnsigned {
		return 0, p.fail(CBORType)
	}
	if f := order.next(p.data[start:p.offset]); f != OK {
		return 0, p.fail(f)
	}
	return key, true
}

func (p *parser) scanFail(f Failure) scan {
	p.fail(f)
	return scanInvalid
}

func (p *parser) scanArgument() (uint8, uint64, scan) {
	truncated := false
	major, value, ok := p.argument(func() bool {
		truncated = true
		return false
	})
	if truncated {
		return 0, 0, scanTruncated
	}
	if !ok {
		return 0, 0, scanInvalid
	}
	return major, value, scanOK
}

func (p *parser) scanItem(depth int, limitedMajor uint8, limit uint64) scan {
	major, count, result := p.scanArgument()
	if result != scanOK {
		return result
	}
	if major == limitedMajor && count > limit {
		return p.scanFail(ResourceLimit)
	}
	switch major {
	case majorUnsigned:
		return scanOK
	case majorNegative:
		return p.scanFail(CBORType)
	case majorBytes, majorText:
		if count > uint64(decodedStringsMax-p.decoded) {
			return p.scanFail(ResourceLimit)
		}
		p.decoded += int(count)
		if count > uint64(len(p.data)-p.offset) {
			return scanTruncated
		}
		value := p.data[p.offset : p.offset+int(count)]
		p.offset += int(count)
		if major == majorBytes {
			return scanOK
		}
		if f := checkText(value); f != OK {
			return p.scanFail(f)
		}
		return scanOK
	case majorArray:
		if depth > depthMax {
			return p.scanFail(ResourceLimit)
		}
		for i := uint64(0); i < count; i++ {
			if result := p.scanItem(depth+1, majorNone, 0); result != scanOK {
				return result
			}
		}
		return scanOK
	case majorMap:
		if depth > depthMax {
			return p.scanFail(ResourceLimit)
		}
		var order keyOrder
		for i := uint64(0); i < count; i++ {
			start := p.offset
			keyMajor, key, result := p.scanArgument()
			if result != scanOK {
				return result
			}
			if keyMajor == majorTag {
				return p.scanFail(CBORTag)
			}
			if keyMajor != majorUnsigned {
				return p.scanFail(CBORType)
			}
			if f := order.next(p.data[start:p.offset]); f != OK {
				return p.scanFail(f)
			}
			childMajor, childLimit := uint8(majorNone), uint64(0)
			if depth == 1 {
				childMajor, childLimit = topLevelLimit(key)
			}
			if result := p.scanItem(depth+1, childMajor, childLimit); result != scanOK {
				return result
			}
		}
		return scanOK
	case majorTag:
		return p.scanFail(CBORTag)
	default:
		if count == 20 || count == 21 {
			return scanOK
		}
		return p.scanFail(CBORType)
	}
}

func topLevelLimit(key uint64) (uint8, uint64) {
	switch key {
	case 8:
		return majorArray, entryPointsMax
	case 9:
		return majorArray, InventoryMax
	case 10:
		return majorArray, resourcesMax
	case 11:
		return majorArray, iconsMax
	case 12:
		return majorArray, grantsMax
	case 13:
		return majorArray, portalsMax
	case 16:
		return majorMap, extensionsMax
	}
	return majorNone, 0
}

func preflight(data []byte) Failure {
	p := parser{data: data}
	switch p.scanItem(1, majorNone, 0) {
	case scanTruncated:
		return CBORType
	case scanInvalid:
		return p.failure
	}
	if p.offset != len(p.data) {
		return CBORTrailing
	}
	return OK
}
