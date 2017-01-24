package merkle

import (
	"bytes"
	"github.com/syndtr/goleveldb/leveldb"
	. "github.com/zballs/pos/util"
	"path/filepath"
	"strconv"
)

// This merkle tree has a leveldb which
// stores the parent hashes of the values
// contained in a graph..

type Tree struct {
	batch     *leveldb.Batch
	db        *leveldb.DB
	leafCount int64
	nodeCount int64
	numLeaves int64
	numNodes  int64
	value     []byte
}

func (t *Tree) String() string {
	return Sprintf("TREE(num_leaves=%d,num_nodes=%d,value=%x)", t.numLeaves, t.numNodes, t.value)
}

func NewTree(treeId int) (t *Tree, err error) {
	t = new(Tree)
	t.batch = new(leveldb.Batch)
	treePath := filepath.Join("tree", strconv.Itoa(treeId))
	t.db, err = leveldb.OpenFile(treePath, nil)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Tree) Init(numLeaves int64) {
	t.numLeaves = numLeaves
	t.numNodes = GetPowOf2(numLeaves) - 1
	t.nodeCount = t.numNodes>>1 + 1
}

func (t *Tree) Root() ([]byte, error) {
	key := Int64Bytes(1)
	value, err := t.db.Get(key, nil)
	if err != nil {
		return nil, err
	}
	return value, nil
}

// 1) Add leaves, set hashes of top-level nodes
// We are assuming the values are topologically sorted
func (t *Tree) AddLeaf(value []byte) error {
	if t.leafCount == t.numLeaves {
		// shouldn't happen..
		return Error("Cannot add leaf; maximum capacity reached")
	}
	if t.leafCount&1 == 0 {
		t.value = value
	} else {
		t.value = append(t.value, value...)
		hash := NewHash()
		hash.Write(t.value)
		key, value := Int64Bytes(t.nodeCount), hash.Sum(nil)
		t.batch.Put(key, value)
		t.value = nil
		t.nodeCount++
		if t.leafCount%BATCH_SIZE == 0 || t.leafCount+1 == t.numLeaves {
			if err := t.db.Write(t.batch, nil); err != nil {
				return err
			}
			t.batch = new(leveldb.Batch)
		}
	}
	t.leafCount++
	return nil
}

// 2) Hash lower-level nodes
func (t *Tree) HashLevels() error {
	if t.leafCount != t.numLeaves {
		// tree does not have all its leaves
		// return err?
	}
	count := 0
	var key, value []byte
	hash := NewHash()
	for t.nodeCount > 0 {
		if t.nodeCount > t.numNodes {
			t.nodeCount = t.numNodes >> 1
		}
		if t.nodeCount > t.numNodes>>1 {
			count++
			if t.value == nil {
				// empty node
				key, value = Int64Bytes(t.nodeCount), t.value
			} else {
				// we have top-level node with one child
				hash.Reset()
				hash.Write(t.value)
				key, value = Int64Bytes(t.nodeCount), hash.Sum(nil)
				t.value = nil
			}
			t.nodeCount++
		} else {
			times2 := t.nodeCount << 1
			keyLeft := Int64Bytes(times2)
			valueLeft, err := t.db.Get(keyLeft, nil)
			if err != nil {
				return err
			}
			keyRight := Int64Bytes(times2 + 1)
			valueRight, err := t.db.Get(keyRight, nil)
			if err != nil {
				return err
			}
			t.value = append(valueLeft, valueRight...)
			hash.Reset()
			hash.Write(t.value)
			key, value = Int64Bytes(t.nodeCount), hash.Sum(nil)
			t.nodeCount--
		}
		if err := t.db.Put(key, value, nil); err != nil {
			return err
		}
	}
	return nil
}

type Proof struct {
	Branch [][]byte `json:"branch"`
	Idx    int64    `json:"idx"`
	Pos    int64    `json:"pos"`
	Value  []byte   `json:"value"`
}

func (mp *Proof) String() string {
	return Sprintf("MERKLE_PROOF(branch_length=%d,idx=%d,pos=%d,value=%x...)\n",
		len(mp.Branch), mp.Idx, mp.Pos, mp.Value[:3])
}

// Get sibling and value from graph
func (t *Tree) ComputeProof(idx int64, sibling, value []byte) (*Proof, error) {
	if idx < 0 {
		return nil, Error("Idxs cannot be less than 0")
	}
	if idx >= t.numLeaves {
		return nil, Errorf("Expected idx < %d; got idx=%d\n", t.numLeaves, idx)
	}
	p := new(Proof)
	p.Branch = append(p.Branch, sibling)
	p.Idx = idx
	pos := idx + t.numNodes + 1
	p.Pos = pos
	p.Value = value
	for {
		if pos >>= 1; pos == 1 {
			return p, nil
		}
		key := Int64Bytes(pos ^ 1)
		val, err := t.db.Get(key, nil)
		if err != nil {
			return nil, err
		}
		p.Branch = append(p.Branch, val)
	}
}

func VerifyProof(p *Proof, root []byte) bool {
	hash := NewHash()
	pos := p.Pos
	value := p.Value
	for _, otherValue := range p.Branch {
		hash.Reset()
		if pos&1 == 0 {
			hash.Write(append(value, otherValue...))
		} else {
			hash.Write(append(otherValue, value...))
		}
		value = hash.Sum(nil)
		pos >>= 1
	}
	return bytes.Equal(root, value)
}
