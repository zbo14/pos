package pos

import (
	"crypto/rand"
	"encoding/binary"
)

const ITER = 3

type BloomFilter []byte

func NewBloomFilter(capacity int64) BloomFilter {
	bytes := make([]byte, 5*capacity/4) // 10 bits per member
	return BloomFilter(bytes)
}

func (bloom BloomFilter) getIdx(pos int64) int64 {
	return int64(len(bloom)-1) - (pos / 8)
}

func (bloom BloomFilter) length() int64 {
	return int64(len(bloom))
}

func (bloom BloomFilter) size() int64 {
	return bloom.length() * 8
}

func (bloom BloomFilter) setBit(pos int64) {
	idx := bloom.getIdx(pos)
	b := bloom[idx]
	b |= (1 << uint64(pos%8))
	bloom[idx] = b
}

func (bloom BloomFilter) hasBit(pos int64) bool {
	idx := bloom.getIdx(pos)
	b := bloom[idx]
	val := b & (1 << uint64(pos%8))
	return (val > 0)
}

// Murmur Hash

const (
	c1     int64 = 0xcc9e2d51
	c2     int64 = 0x1b873593
	n      int64 = 0xe6546b64
	round4 int64 = 0xfffffffc
	seed   int64 = 0x0
)

func (bloom BloomFilter) murmurHash(data []byte, seed int64) int64 {
	h := seed
	length := int64(len(data))
	roundedEnd := length & round4
	var i int64
	var k int64
	for i = 0; i < roundedEnd; i += 4 {
		b0, b1, b2, b3 := data[i], data[i+1], data[i+2], data[i+3]
		k := int64(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
		h = (h << 13) | (h >> 19)
		h = h*5 + n
	}
	k = 0
	val := length & 0x03
	if val == 3 {
		k = int64(data[roundedEnd+2] << 16)
	}
	if val >= 2 {
		k |= int64(data[roundedEnd+1] << 8)
	}
	if val >= 1 {
		k |= int64(data[roundedEnd])
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
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

func (bloom BloomFilter) jenkinsHash(data []byte) int64 {
	var hash int64
	for _, b := range data {
		hash += int64(b)
		hash += (hash << 10)
		hash ^= (hash >> 6)
	}
	hash += (hash << 3)
	hash ^= (hash >> 11)
	hash += (hash << 15)
	return hash
}

func (bloom BloomFilter) Has(data []byte) bool {
	hash := bloom.murmurHash(data, seed)
	var i int64
	for ; i < ITER; i++ {
		hash += bloom.jenkinsHash(data)
		pos := hash % bloom.size()
		if !bloom.hasBit(pos) {
			return false
		}
	}
	return true
}

func (bloom BloomFilter) setBits(data []byte) {
	randbz := make([]byte, 8)
	rand.Read(randbz)
	seed, _ := binary.Varint(randbz)
	hash := bloom.murmurHash(data, seed)
	size := bloom.size()
	var i int64
	for ; i < ITER; i++ {
		hash += bloom.jenkinsHash(data)
		pos := hash % size
		if !bloom.hasBit(pos) {
			bloom.setBit(pos)
		}
	}
}

func (bloom BloomFilter) Add(data []byte) bool {
	if bloom.Has(data) {
		return false
	}
	bloom.setBits(data)
	return true
}
