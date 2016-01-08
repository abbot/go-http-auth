// Package bitset implments a memory efficient bit array of booleans
// Adapted from https://github.com/lazybeaver/bitset

package auth

import "fmt"

type BitSet struct {
	bits []uint8
	size uint64
}

const (
	bitMaskZero = uint8(0)
	bitMaskOnes = uint8((1 << 8) - 1)
)

var (
	bitMasks = [...]uint8{0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80}
)

func (b *BitSet) getPositionAndMask(index uint64) (uint64, uint8) {
	if index < 0 || index >= b.size {
		panic(fmt.Errorf("BitSet index (%d) out of bounds (size: %d)", index, b.size))
	}
	position := index >> 3
	mask := bitMasks[index%8]
	return position, mask
}

func (b *BitSet) Init(size uint64) {
	b.bits = make([]uint8, (size+7)/8)
	b.size = size
}

func (b *BitSet) Size() uint64 {
	return b.size
}

func (b *BitSet) Get(index uint64) bool {
	position, mask := b.getPositionAndMask(index)
	return (b.bits[position] & mask) != 0
}

func (b *BitSet) Set(index uint64) {
	position, mask := b.getPositionAndMask(index)
	b.bits[position] |= mask
}

func (b *BitSet) Clear(index uint64) {
	position, mask := b.getPositionAndMask(index)
	b.bits[position] &^= mask
}

func (b *BitSet) String() string {
	value := make([]byte, b.size)
	var i uint64
	for i = 0; i < b.size; i++ {
		if b.Get(i) {
			value[i] = '1'
		} else {
			value[i] = '0'
		}
	}
	return string(value)
}

func NewBitSet(size uint64) *BitSet {
	b := &BitSet{}
	b.Init(size)
	return b
}
