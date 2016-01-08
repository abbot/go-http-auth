package auth

import (
	"testing"
)

func TestNew(t *testing.T) {
	var size uint64 = 101
	bs := NewBitSet(size)
	if bs.Size() != size {
		t.Errorf("Unexpected initialization failure")
	}
	var i uint64
	for i = 0; i < size; i++ {
		if bs.Get(i) {
			t.Errorf("Newly initialized bitset cannot have true values")
		}
	}
}

func TestGet(t *testing.T) {
	bs := NewBitSet(2)
	bs.Set(0)
	bs.Clear(1)
	if bs.Get(0) != true {
		t.Errorf("Actual: false | Expected: true")
	}
	if bs.Get(1) != false {
		t.Errorf("Actual: true | Expected: false")
	}
}

func TestSet(t *testing.T) {
	bs := NewBitSet(10)
	bs.Set(2)
	bs.Set(3)
	bs.Set(5)
	bs.Set(7)
	actual := bs.String()
	expected := "0011010100"
	if actual != expected {
		t.Errorf("Actual: %s | Expected: %s", actual, expected)
	}
}

func TestClear(t *testing.T) {
	bs := NewBitSet(10)
	var i uint64
	for i = 0; i < 10; i++ {
		bs.Set(i)
	}
	bs.Clear(0)
	bs.Clear(3)
	bs.Clear(6)
	bs.Clear(9)
	actual := bs.String()
	expected := "0110110110"
	if actual != expected {
		t.Errorf("Actual: %s | Expected: %s", actual, expected)
	}
}

func BenchmarkGet(b *testing.B) {
	bn := uint64(b.N)
	bs := NewBitSet(bn)
	var i uint64
	for i = 0; i < bn; i++ {
		_ = bs.Get(i)
	}
}

func BenchmarkSet(b *testing.B) {
	bn := uint64(b.N)
	bs := NewBitSet(bn)
	var i uint64
	for i = 0; i < bn; i++ {
		bs.Set(i)
	}
}
