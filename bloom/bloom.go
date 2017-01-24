package bloom

import (
	"crypto/rand"
	"encoding/binary"
)

const ITERS = 3

type Filter struct {
	bytes []byte
	seed  uint64
}

func NewFilter(capacity int) *Filter {
	// at least 10 bits per item
	var length int
	size := 10 * capacity
	if length = size / 8; size%8 != 0 {
		length++
	}
	bytes := make([]byte, length)
	buf := make([]byte, 8)
	rand.Read(buf)
	seed := binary.BigEndian.Uint64(buf)
	return &Filter{
		bytes: bytes,
		seed:  seed,
	}
}

func (f *Filter) getIdx(pos uint64) uint64 {
	return uint64(len(f.bytes)-1) - (pos / 8)
}

func (f *Filter) length() uint64 {
	return uint64(len(f.bytes))
}

func (f *Filter) size() uint64 {
	return f.length() * 8
}

func (f *Filter) setBit(pos uint64) {
	idx := f.getIdx(pos)
	b := f.bytes[idx]
	b |= (1 << (pos % 8))
	f.bytes[idx] = b
}

func (f *Filter) hasBit(pos uint64) bool {
	idx := f.getIdx(pos)
	b := f.bytes[idx]
	val := b & (1 << (pos % 8))
	return (val > 0)
}

// Murmur Hash

const (
	C1     uint64 = 0xcc9e2d51
	C2     uint64 = 0x1b873593
	N      uint64 = 0xe6546b64
	ROUND4 uint64 = 0xfffffffc
)

func MurmurHash(bytes []byte, seed uint64) uint64 {
	h := seed
	length := uint64(len(bytes))
	roundedEnd := length & ROUND4
	var i uint64
	var k uint64
	for i = 0; i < roundedEnd; i += 4 {
		b0, b1, b2, b3 := bytes[i], bytes[i+1], bytes[i+2], bytes[i+3]
		k := uint64(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
		k *= C1
		k = (k << 15) | (k >> 17)
		k *= C2
		h ^= k
		h = (h << 13) | (h >> 19)
		h = h*5 + N
	}
	k = 0
	val := length & 0x03
	if val == 3 {
		k = uint64(bytes[roundedEnd+2] << 16)
	}
	if val >= 2 {
		k |= uint64(bytes[roundedEnd+1] << 8)
	}
	if val >= 1 {
		k |= uint64(bytes[roundedEnd])
		k *= C1
		k = (k << 15) | (k >> 17)
		k *= C2
		h ^= k
	}
	h ^= length
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

// FNV Hash

const (
	FNV_OFFSET_BASIS uint64 = 0xcbf29ce484222325
	FNV_PRIME        uint64 = 0x100000001b3
)

func FnvHash(bytes []byte) uint64 {
	hash := FNV_OFFSET_BASIS
	for _, b := range bytes {
		hash *= FNV_PRIME
		hash |= uint64(b)
	}
	return hash
}

// Jenkins Hash

func JenkinsHash(bytes []byte) uint64 {
	var hash uint64
	for _, b := range bytes {
		hash += uint64(b)
		hash += (hash << 10)
		hash ^= (hash >> 6)
	}
	hash += (hash << 3)
	hash ^= (hash >> 11)
	hash += (hash << 15)
	return hash
}

func (f *Filter) Has(bytes []byte) bool {
	hash := MurmurHash(bytes, f.seed)
	size := f.size()
	var i uint64
	for ; i < ITERS; i++ {
		hash += FnvHash(bytes)
		pos := hash % size
		if !f.hasBit(pos) {
			return false
		}
	}
	return true
}

func (f *Filter) setBits(bytes []byte) {
	hash := MurmurHash(bytes, f.seed)
	size := f.size()
	var i uint64
	for ; i < ITERS; i++ {
		hash += FnvHash(bytes)
		pos := hash % size
		if !f.hasBit(pos) {
			f.setBit(pos)
		}
	}
}

func (f *Filter) Add(bytes []byte) bool {
	if f.Has(bytes) {
		return false
	}
	f.setBits(bytes)
	f.count++
	return true
}
