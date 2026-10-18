package cose

import (
	"bytes"
	"encoding/binary"
	"errors"
)

var errMalformed = errors.New("cose: malformed structure")

const maxStructure = 65536

type reader struct {
	data   []byte
	offset int
}

func (r *reader) head() (major byte, value uint64, err error) {
	if r.offset >= len(r.data) {
		return 0, 0, errMalformed
	}
	initial := r.data[r.offset]
	r.offset++
	major = initial >> 5
	additional := initial & 0x1f
	if additional < 24 {
		return major, uint64(additional), nil
	}
	if additional > 27 {
		return 0, 0, errMalformed
	}
	size := 1 << (additional - 24)
	if size > len(r.data)-r.offset {
		return 0, 0, errMalformed
	}
	for i := 0; i < size; i++ {
		value = value<<8 | uint64(r.data[r.offset])
		r.offset++
	}
	if (size == 1 && value < 24) || (size == 2 && value <= 0xff) ||
		(size == 4 && value <= 0xffff) || (size == 8 && value <= 0xffffffff) {
		return 0, 0, errMalformed
	}
	if major == 7 {
		return 0, 0, errMalformed
	}
	return major, value, nil
}

func (r *reader) expect(major byte) (uint64, error) {
	got, value, err := r.head()
	if err != nil {
		return 0, err
	}
	if got != major {
		return 0, errMalformed
	}
	return value, nil
}

func (r *reader) bytesOf(major byte) ([]byte, error) {
	length, err := r.expect(major)
	if err != nil {
		return nil, err
	}
	if length > uint64(len(r.data)-r.offset) {
		return nil, errMalformed
	}
	out := r.data[r.offset : r.offset+int(length)]
	r.offset += int(length)
	return out, nil
}

func (r *reader) simple() (byte, error) {
	if r.offset >= len(r.data) {
		return 0, errMalformed
	}
	b := r.data[r.offset]
	r.offset++
	return b, nil
}

func (r *reader) done() error {
	if r.offset != len(r.data) {
		return errMalformed
	}
	return nil
}

type label struct {
	encoded []byte
	value   int64
	text    string
	isText  bool
}

func (r *reader) label(previous []byte) (label, error) {
	start := r.offset
	major, value, err := r.head()
	if err != nil {
		return label{}, err
	}
	var l label
	switch major {
	case 0:
		if value > 1<<62 {
			return label{}, errMalformed
		}
		l.value = int64(value)
	case 1:
		if value > 1<<62 {
			return label{}, errMalformed
		}
		l.value = -1 - int64(value)
	case 3:
		if value > uint64(len(r.data)-r.offset) {
			return label{}, errMalformed
		}
		l.text = string(r.data[r.offset : r.offset+int(value)])
		l.isText = true
		r.offset += int(value)
	default:
		return label{}, errMalformed
	}
	l.encoded = r.data[start:r.offset]
	if previous != nil && bytes.Compare(previous, l.encoded) >= 0 {
		return label{}, errMalformed
	}
	return l, nil
}

type writer struct {
	bytes.Buffer
}

func (w *writer) head(major byte, value uint64) {
	switch {
	case value < 24:
		w.WriteByte(major<<5 | byte(value))
	case value <= 0xff:
		w.WriteByte(major<<5 | 24)
		w.WriteByte(byte(value))
	case value <= 0xffff:
		w.WriteByte(major<<5 | 25)
		w.Write(binary.BigEndian.AppendUint16(nil, uint16(value)))
	case value <= 0xffffffff:
		w.WriteByte(major<<5 | 26)
		w.Write(binary.BigEndian.AppendUint32(nil, uint32(value)))
	default:
		w.WriteByte(major<<5 | 27)
		w.Write(binary.BigEndian.AppendUint64(nil, value))
	}
}

func (w *writer) int(value int64) {
	if value < 0 {
		w.head(1, uint64(-1-value))
		return
	}
	w.head(0, uint64(value))
}

func (w *writer) bytesValue(major byte, value []byte) {
	w.head(major, uint64(len(value)))
	w.Write(value)
}
