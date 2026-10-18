package wire

import (
	"sort"
	"unicode/utf8"
)

type decomposition struct {
	point  uint32
	offset uint32
	count  uint32
}

type combiningClass struct {
	point uint32
	class uint8
}

type composition struct {
	pair  uint64
	point uint32
}

func validUTF8(value []byte) (ascii bool, valid bool) {
	ascii = true
	for i := 0; i < len(value); {
		first := value[i]
		i++
		if first < 0x80 {
			continue
		}
		ascii = false
		var remaining int
		switch {
		case first >= 0xc2 && first <= 0xdf:
			remaining = 1
		case first >= 0xe0 && first <= 0xef:
			remaining = 2
		case first >= 0xf0 && first <= 0xf4:
			remaining = 3
		default:
			return ascii, false
		}
		if remaining > len(value)-i {
			return ascii, false
		}
		second := value[i]
		if second&0xc0 != 0x80 {
			return ascii, false
		}
		if (first == 0xe0 && second < 0xa0) ||
			(first == 0xed && second >= 0xa0) ||
			(first == 0xf0 && second < 0x90) ||
			(first == 0xf4 && second >= 0x90) {
			return ascii, false
		}
		for remaining--; remaining != 0; remaining-- {
			i++
			if value[i]&0xc0 != 0x80 {
				return ascii, false
			}
		}
		i++
	}
	return ascii, true
}

func classOf(point uint32) uint8 {
	i := sort.Search(len(unicodeClasses), func(i int) bool { return unicodeClasses[i].point >= point })
	if i < len(unicodeClasses) && unicodeClasses[i].point == point {
		return unicodeClasses[i].class
	}
	return 0
}

func decompositionOf(point uint32) []uint32 {
	i := sort.Search(len(unicodeDecompositions), func(i int) bool { return unicodeDecompositions[i].point >= point })
	if i < len(unicodeDecompositions) && unicodeDecompositions[i].point == point {
		d := unicodeDecompositions[i]
		return unicodePoints[d.offset : d.offset+d.count]
	}
	return nil
}

func compose(first, second uint32) uint32 {
	if first >= 0x1100 && first < 0x1113 && second >= 0x1161 && second < 0x1176 {
		return 0xac00 + (first-0x1100)*588 + (second-0x1161)*28
	}
	if first >= 0xac00 && first <= 0xd7a3 && (first-0xac00)%28 == 0 && second > 0x11a7 && second < 0x11c3 {
		return first + second - 0x11a7
	}
	pair := uint64(first)<<21 | uint64(second)
	i := sort.Search(len(unicodeCompositions), func(i int) bool { return unicodeCompositions[i].pair >= pair })
	if i < len(unicodeCompositions) && unicodeCompositions[i].pair == pair {
		return unicodeCompositions[i].point
	}
	return 0
}

func isNFC(value []byte) bool {
	if len(value) == 0 {
		return true
	}
	original := make([]uint32, 0, len(value))
	points := make([]uint32, 0, len(value)*2)
	for i := 0; i < len(value); {
		r, size := utf8.DecodeRune(value[i:])
		i += size
		point := uint32(r)
		original = append(original, point)
		if point >= 0xac00 && point <= 0xd7a3 {
			syllable := point - 0xac00
			points = append(points, 0x1100+syllable/588, 0x1161+(syllable%588)/28)
			if syllable%28 != 0 {
				points = append(points, 0x11a7+syllable%28)
			}
		} else if d := decompositionOf(point); d != nil {
			points = append(points, d...)
		} else {
			points = append(points, point)
		}
	}
	for start := 0; start < len(points); {
		if classOf(points[start]) == 0 {
			start++
		}
		end := start
		for end < len(points) && classOf(points[end]) != 0 {
			end++
		}
		if end-start > 1 {
			run := points[start:end]
			sort.SliceStable(run, func(a, b int) bool { return classOf(run[a]) < classOf(run[b]) })
		}
		start = end
	}
	output := 0
	starter := -1
	var previous uint8
	for _, point := range points {
		class := classOf(point)
		var composite uint32
		if starter >= 0 && (previous == 0 || previous < class) {
			composite = compose(points[starter], point)
		}
		if composite != 0 {
			points[starter] = composite
			continue
		}
		if class == 0 {
			starter = output
		}
		points[output] = point
		output++
		previous = class
	}
	if output != len(original) {
		return false
	}
	for i := range original {
		if original[i] != points[i] {
			return false
		}
	}
	return true
}
