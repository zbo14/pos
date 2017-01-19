package util

import (
	"crypto/rand"
	"encoding/binary"
	"golang.org/x/crypto/sha3"
	"hash"
	"math"
)

const (
	BATCH_SIZE int64 = 100
	HASH_SIZE        = 32
)

func NewHash() hash.Hash {
	switch HASH_SIZE {
	case 32:
		return NewHash32()
	case 64:
		return NewHash64()
	default:
		panic("Invalid hash size")
	}
}

func NewHash32() hash.Hash {
	return sha3.New256()
}

func NewHash64() hash.Hash {
	return sha3.New512()
}

func Shake(hash, data []byte) {
	sha3.ShakeSum256(hash, data)
}

func PowOf2(i int64) bool {
	return i != 0 && (i&(i-1)) == 0
}

func Pow2(i int64) int64 {
	return 1 << uint64(i)
}

func GetPowOf2(i int64) int64 {
	if PowOf2(i) {
		return i
	}
	log2 := Log2(i)
	return Pow2(log2)
}

// Calculates log base 2 of i
// If i is not a power of 2
// returns log of next power of 2
func Log2(i int64) int64 {
	var j, l int64 = i, 0
	for {
		if j >>= 1; j == 0 {
			break
		}
		l++
	}
	if PowOf2(i) {
		return l
	}
	return l + 1
}

func Rand(max int64) int64 {
	buf := make([]byte, 8)
	rand.Read(buf)
	i, _ := binary.Varint(buf)
	if i < 0 {
		i *= -1
	}
	i %= max
	return i
}

func EvenSquare(n int64) bool {
	sqrt := math.Sqrt(float64(n))
	return float64(int64(sqrt)) != sqrt
}

// Generates a random sequence with length l
// Numbers lie on the interval [min, max)

func Randz(l, max, min int64) []int64 {
	var idxs []int64
	for {
		if int64(len(idxs)) == l {
			break
		}
		i := Rand(max)
		if i < min {
			continue
		}
		idxs = append(idxs, i)
	}
	return idxs
}

//no repeats
func UniqueRandz(l, max, min int64) []int64 {
	var idxs []int64
FOR_LOOP:
	for {
		if int64(len(idxs)) == l {
			break
		}
		i := Rand(max)
		if i < min {
			continue
		}
		for _, idx := range idxs {
			if i == idx {
				continue FOR_LOOP
			}
		}
		idxs = append(idxs, i)
	}
	return idxs
}

func Int64Bytes(i int64) []byte {
	buf := make([]byte, 8)
	binary.PutVarint(buf, i)
	return buf
}

type Int64s []int64

func (i64s Int64s) Len() int {
	return len(i64s)
}

func (i64s Int64s) Size() int64 {
	return int64(len(i64s))
}

func (i64s Int64s) Less(i, j int) bool {
	return i64s[i] < i64s[j]
}

func (i64s Int64s) Swap(i, j int) {
	i64s[i], i64s[j] = i64s[j], i64s[i]
}

// Check err
func Check(err error) {
	if err != nil {
		panic(err)
	}
}
