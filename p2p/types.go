package p2p

import (
	"bytes"
	"github.com/zballs/pos/merkle"
	. "github.com/zballs/pos/util"
	"golang.org/x/crypto/ripemd160"
	"io"
	"sync"
)

// From github.com/jaekwon/twirl/types/part_set

var (
	ErrPartSetUnexpectedIndex = Error("Error part set unexpected index")
	ErrPartSetInvalidProof    = Error("Error part set invalid roof")
)

// Bit Array

type BitArray []byte

func (bits BitArray) Len() int {
	return len(bits)
}

func (bits BitArray) Size() int {
	return bits.Len() * 8
}

func NewBitArray(size int) BitArray {
	var length int
	if length = size / 8; size%8 != 0 {
		length++
	}
	bits := make(BitArray, length)
	return bits
}

func (bits BitArray) Has(idx int) (bool, error) {
	if size := bits.Size(); idx > size {
		return false, Errorf("Expected idx < %d; got idx=%d\n", size, idx)
	}
	b := idx / 8
	rem := idx % 8
	if bits[b]&(1<<uint8(7-rem)) == 0 {
		return false, nil
	}
	return true, nil
}

func (bits BitArray) Set(idx int) (bool, error) {
	if size := bits.Size(); idx > size {
		return false, Errorf("Expected idx < %d; got idx=%d\n", size, idx)
	}
	b := idx / 8
	rem := idx % 8
	if bits[b]&(1<<uint8(7-rem)) == 1 {
		return false, nil
	}
	bits[b] |= (1 << uint8(7-rem))
	return true, nil
}

// Part

type Part struct {
	Bytes []byte
	hash  []byte
	Idx   int
	Proof *merkle.MemProof
}

func (part *Part) Hash() []byte {
	if part.hash != nil {
		return part.hash
	}
	hash := ripemd160.New()
	hash.Write(part.Bytes)
	part.hash = hash.Sum(nil)
	return part.hash
}

// PartSetHeader

type PartSetHeader struct {
	Hash  []byte
	Total int
}

func (header PartSetHeader) IsZero() bool {
	return header.Total == 0
}

func (header PartSetHeader) Equals(other PartSetHeader) bool {
	return header.Total == other.Total && bytes.Equal(header.Hash, other.Hash)
}

// PartSet

type PartSet struct {
	bits  BitArray
	count int
	hash  []byte
	mtx   sync.RWMutex
	parts []*Part
	total int
}

func NewPartSetFromData(data []byte, partSize int) (*PartSet, error) {
	total := (len(data) + partSize - 1) / partSize
	values := make([][]byte, total)
	parts := make([]*Part, total)
	bits := NewBitArray(total)
	var start, end int
	for i := 0; i < total; i++ {
		start = i * partSize
		if end = (i + 1); end > len(data) {
			end = len(data)
		}
		part := &Part{
			Bytes: data[start:end],
			Idx:   i,
		}
		hash := part.Hash()
		set, err := bits.Set(i)
		if err != nil {
			return nil, err
		} else if !set {
			//..
		}
		parts[i] = part
		values[i] = hash
	}
	tree := new(merkle.MemTree)
	if err := tree.Construct(values); err != nil {
		return nil, err
	}
	rootHash, err := tree.HashLevels()
	if err != nil {
		return nil, err
	}
	for i := 0; i < total; i++ {
		parts[i].Proof, err = tree.ComputeMemProof(i)
		if err != nil {
			return nil, err
		}
	}
	return &PartSet{
		bits:  bits,
		count: total,
		hash:  rootHash,
		parts: parts,
		total: total,
	}, nil
}

func NewPartSetFromHeader(header PartSetHeader) *PartSet {
	bits := NewBitArray(header.Total)
	parts := make([]*Part, header.Total)
	return &PartSet{
		bits:  bits,
		hash:  header.Hash,
		total: header.Total,
		parts: parts,
	}
}

func (partSet *PartSet) Header() (header PartSetHeader) {
	if partSet == nil {
		return header
	}
	header.Hash = partSet.hash
	header.Total = partSet.total
	return header
}

func (partSet *PartSet) HasHeader(header PartSetHeader) bool {
	if partSet == nil {
		return false
	}
	return partSet.Header().Equals(header)
}

func (partSet *PartSet) Bits() BitArray {
	partSet.mtx.RLock()
	defer partSet.mtx.RUnlock()
	bits := make(BitArray, partSet.bits.Len())
	copy(bits, partSet.bits)
	return bits
}

func (partSet *PartSet) Count() int {
	if partSet == nil {
		return 0
	}
	return partSet.count
}

func (partSet *PartSet) Hash() []byte {
	if partSet == nil {
		return nil
	}
	return partSet.hash
}

func (partSet *PartSet) HashesTo(hash []byte) bool {
	if partSet == nil {
		return false
	}
	return bytes.Equal(partSet.hash, hash)
}

func (partSet *PartSet) AddPart(p *Part) (bool, error) {
	partSet.mtx.Lock()
	defer partSet.mtx.Unlock()
	if p.Idx >= partSet.total {
		return false, ErrPartSetUnexpectedIndex
	}
	if partSet.parts[p.Idx] != nil {
		return false, nil
	}
	if !merkle.VerifyMemProof(p.Proof, partSet.hash) {
		return false, ErrPartSetInvalidProof
	}
	partSet.parts[p.Idx] = p
	set, err := partSet.bits.Set(p.Idx)
	if err != nil {
		return false, err
	} else if !set {
		//..
	}
	partSet.count++
	return true, nil
}

func (partSet *PartSet) GetPart(idx int) *Part {
	partSet.mtx.RLock()
	defer partSet.mtx.RUnlock()
	return partSet.parts[idx]
}

func (partSet *PartSet) IsComplete() bool {
	return partSet.count == partSet.total
}

func (partSet *PartSet) GetReader() io.Reader {
	if !partSet.IsComplete() {
		panic("Cannot get reader on incomplete set")
	}
	return NewPartSetReader(partSet.parts)
}

type PartSetReader struct {
	idx    int
	parts  []*Part
	reader *bytes.Reader
}

func NewPartSetReader(parts []*Part) *PartSetReader {
	reader := bytes.NewReader(parts[0].Bytes)
	return &PartSetReader{
		idx:    0,
		parts:  parts,
		reader: reader,
	}
}

// Iterative read
func (r *PartSetReader) Read(p []byte) (int, error) {
	var err error
	var n, read int
	size := len(p)
	for idx := r.idx; idx < len(r.parts); {
		length := r.reader.Len()
		if length >= size-read {
			n, err = r.reader.Read(p[read:])
			return read + n, err
		}
		if length > 0 {
			n, err = r.Read(p[read : read+length])
			if err != nil {
				return read + n, err
			}
			read += n
		}
		idx++
		r.reader = bytes.NewReader(r.parts[idx].Bytes)
	}
	return read, io.EOF
}
