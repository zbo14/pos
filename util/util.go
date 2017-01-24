package util

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
	"hash"
	"io"
	"io/ioutil"
	"math"
	"math/big"
	mathrand "math/rand"
	"os"
	"strings"
)

const (
	BATCH_SIZE int64 = 100
	HASH_SIZE        = 32
)

// JSON

func MarshalJSON(v interface{}) []byte {
	data, err := json.Marshal(v)
	Check(err)
	return data
}

func UnmarshalJSON(data []byte, v interface{}) {
	err := json.Unmarshal(data, v)
	Check(err)
}

// Hash

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

func Shake32(hash, data []byte) {
	sha3.ShakeSum256(hash, data)
}

func Sum32(data []byte) []byte {
	sum := sha3.Sum256(data)
	return sum[:]
}

func Sum64(data []byte) []byte {
	sum := sha3.Sum512(data)
	return sum[:]
}

// Exp

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

func EvenSquare(n int64) bool {
	sqrt := math.Sqrt(float64(n))
	return float64(int64(sqrt)) != sqrt
}

// Float

var eps = big.NewFloat(float64(0.00000001))
var zero = big.NewFloat(float64(0))
var one = big.NewFloat(float64(1))

func Exp2(x float64) float64 {
	return math.Exp2(x)
}

func BytesToFloat(data []byte) *big.Float {
	bigint := new(big.Int).SetBytes(data)
	return new(big.Float).SetInt(bigint)
}

func BigPow(a *big.Float, n int64) *big.Float {
	exp := new(big.Float).Copy(a)
	if n < 0 {
		exp.Quo(one, exp)
		n = -n
	} else if n == 0 {
		return one
	}
	x := new(big.Float).Copy(one)
	for i := n; i > 1; i >>= 1 {
		if i&1 == 1 {
			x.Mul(exp, x)
		}
		exp.Mul(exp, exp)
	}
	return exp.Mul(exp, x)
}

func NRoot(a *big.Float, n int64) *big.Float {
	mult := new(big.Float).Copy(one)
	mult.Quo(mult, big.NewFloat(float64(n)))
	x := new(big.Float).Mul(a, mult)
	d := new(big.Float)
	for {
		exp := BigPow(x, n-1)
		d.Quo(a, exp).Sub(d, x).Mul(d, mult)
		if d.Cmp(eps) < 0 && d.Cmp(zero) >= 0 {
			return x
		}
		x.Add(x, d)
	}
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

func RandPerm(n int) []int {
	return mathrand.Perm(n)
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

// Errors

func Error(msg string) error {
	return errors.New(msg)
}

func Errorf(format string, args ...interface{}) error {
	return errors.Errorf(format, args...)
}

func Check(err error) {
	if err != nil {
		panic(err)
	}
}

func Panicf(format string, args ...interface{}) {
	panic(Sprintf(format+"\n", args...))
}

// Fmt

var (
	Sprintf = fmt.Sprintf
	Println = fmt.Println
	Printf  = fmt.Printf
)

// io

func ReadAll(r io.Reader) ([]byte, error) {
	return ioutil.ReadAll(r)
}

func MustReadAll(r io.Reader) []byte {
	bytes, err := ReadAll(r)
	Check(err)
	return bytes
}

func ReadFull(r io.Reader, buf []byte) (int, error) {
	return io.ReadFull(r, buf)
}

func MustReadFull(r io.Reader, buf []byte) {
	n, err := ReadFull(r, buf)
	Check(err)
	if size := len(buf); n != size {
		Panicf("Expected to have read %d bytes; only read %d", size, n)
	}
}

// os

func ReadFile(path string) ([]byte, error) {
	return ioutil.ReadFile(path)
}

func MustReadFile(path string) []byte {
	bytes, err := ReadFile(path)
	Check(err)
	return bytes
}

func WriteFile(path string, contents []byte, mode os.FileMode) error {
	if err := ioutil.WriteFile(path, contents, mode); err != nil {
		return err
	}
	return nil
}

func MustWriteFile(path string, contents []byte, mode os.FileMode) {
	err := WriteFile(path, contents, mode)
	Check(err)
}

func Exit(msg string) {
	Println(msg)
	os.Exit(1)
}

func ExitErr(err error) {
	Println(err.Error())
	os.Exit(1)
}

func Exitf(format string, args ...interface{}) {
	Printf(format, args...)
	os.Exit(1)
}

// strings

func Split(s, sep string) []string {
	return strings.Split(s, sep)
}

func Split2(s, sep string) (string, string, error) {
	strs := strings.SplitN(s, sep, 2)
	if len(strs) != 2 {
		return "", "", Errorf("Could not split str=%s with sep=%s", s, sep)
	}
	return strs[0], strs[1], nil
}
