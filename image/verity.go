package image

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

const (
	BlockSize      = 4096
	superblockSize = 512
	hashesPerBlock = BlockSize / sha256.Size
	hashPerBits    = 7
)

var ErrAlignment = errors.New("image: data is not a whole number of blocks")

type Verity struct {
	Salt       [32]byte
	UUID       [16]byte
	DataBlocks uint64
	RootHash   [sha256.Size]byte
	Tree       []byte
}

func levels(dataBlocks uint64) int {
	n := 0
	for hashPerBits*n < 64 && (dataBlocks-1)>>(hashPerBits*uint(n)) != 0 {
		n++
	}
	return n
}

func digest(salt []byte, block []byte) [sha256.Size]byte {
	h := sha256.New()
	h.Write(salt)
	h.Write(block)
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func superblock(v *Verity) []byte {
	sb := make([]byte, BlockSize)
	copy(sb, "verity\x00\x00")
	binary.LittleEndian.PutUint32(sb[8:], 1)
	binary.LittleEndian.PutUint32(sb[12:], 1)
	copy(sb[16:32], v.UUID[:])
	copy(sb[32:64], "sha256")
	binary.LittleEndian.PutUint32(sb[64:], BlockSize)
	binary.LittleEndian.PutUint32(sb[68:], BlockSize)
	binary.LittleEndian.PutUint64(sb[72:], v.DataBlocks)
	binary.LittleEndian.PutUint16(sb[80:], uint16(len(v.Salt)))
	copy(sb[88:], v.Salt[:])
	return sb
}

func Format(data io.ReaderAt, size int64, salt [32]byte, uuid [16]byte) (*Verity, error) {
	if size <= 0 || size%BlockSize != 0 {
		return nil, ErrAlignment
	}
	v := &Verity{Salt: salt, UUID: uuid, DataBlocks: uint64(size / BlockSize)}
	block := make([]byte, BlockSize)
	var current [][sha256.Size]byte
	for i := uint64(0); i < v.DataBlocks; i++ {
		if _, err := data.ReadAt(block, int64(i)*BlockSize); err != nil {
			return nil, err
		}
		current = append(current, digest(salt[:], block))
	}
	n := levels(v.DataBlocks)
	if n == 0 {
		v.RootHash = current[0]
		v.Tree = superblock(v)
		return v, nil
	}
	var stored [][]byte
	for level := 0; level < n; level++ {
		count := (len(current) + hashesPerBlock - 1) / hashesPerBlock
		area := make([]byte, count*BlockSize)
		next := make([][sha256.Size]byte, 0, count)
		for b := 0; b < count; b++ {
			page := area[b*BlockSize : (b+1)*BlockSize]
			for j := 0; j < hashesPerBlock && b*hashesPerBlock+j < len(current); j++ {
				copy(page[j*sha256.Size:], current[b*hashesPerBlock+j][:])
			}
			next = append(next, digest(salt[:], page))
		}
		stored = append(stored, area)
		current = next
	}
	v.RootHash = current[0]
	tree := superblock(v)
	for level := n - 1; level >= 0; level-- {
		tree = append(tree, stored[level]...)
	}
	v.Tree = tree
	return v, nil
}
