package merkle

import (
	"bytes"
	. "github.com/zbo14/pos/util"
	"golang.org/x/crypto/ripemd160"
)

// Simple merkle tree in memory

// TODO: add String() methods

type Node struct {
	hash        []byte
	left, right *Node
	parent      *Node
}

func (nd *Node) Hash() []byte {
	if nd == nil {
		return nil
	}
	return nd.hash
}

func (nd *Node) IsLeaf() bool {
	if nd == nil {
		return false
	}
	return nd.left == nil && nd.right == nil
}

type Level []*Node

type MemTree struct {
	levels []Level
}

type Branch [][]byte

func (t *MemTree) Height() int {
	return len(t.levels)
}

func (t *MemTree) Empty() bool {
	return t.Height() == 0
}

func (t *MemTree) Root() *Node {
	return t.levels[0][0]
}

func (t *MemTree) Level(height int) Level {
	height--
	if height < 0 {
		panic("Height cannot be less than 0")
	}
	if max := t.Height(); height > max {
		Panicf("Height cannot be greater than %d\n", max)
	}
	return t.levels[height]
}

type MemProof struct {
	branch Branch
	hash   []byte
	idx    int
}

func NewMemProof(branch Branch, hash []byte) *MemProof {
	return &MemProof{
		branch: branch,
		hash:   hash,
	}
}

func (t *MemTree) ComputeMemProof(idx int) *MemProof {
	if idx < 0 {
		panic("Idx cannot be less than 0")
	}
	height := t.Height()
	leaves := t.Level(height)
	if length := len(leaves); idx >= length {
		Panicf("Expected idx <= %d; got idx=%d\n", length, idx)
	}
	memProof := new(MemProof)
	memProof.idx = idx
	memProof.hash = leaves[idx].hash
	if idx^1 < len(leaves) {
		memProof.branch = append(memProof.branch, leaves[idx^1].hash)
	} else {
		memProof.branch = append(memProof.branch, nil)
	}
	for {
		height--
		level := t.Level(height)
		if len(level) == 1 {
			// We hit root... break
			break
		}
		if idx >>= 1; idx^1 < len(level) {
			memProof.branch = append(memProof.branch, level[idx^1].hash)
		} else {
			memProof.branch = append(memProof.branch, nil)
		}

	}
	return memProof
}

func VerifyMemProof(memProof *MemProof, root []byte) bool {
	branch := memProof.branch
	hash := memProof.hash
	hasher := ripemd160.New()
	idx := memProof.idx
	for _, otherHash := range branch {
		if otherHash != nil {
			if idx&1 == 0 {
				hash = append(hash, otherHash...)
			} else {
				hash = append(otherHash, hash...)
			}
		} else {
			// just hash the previous hash
			// should this happen?
		}
		hasher.Write(hash)
		hash = hasher.Sum(nil)
		hasher.Reset()
		idx >>= 1
	}
	match := bytes.Equal(hash, root)
	return match
}

// (1) Calculates height of tree, creates that many levels
// (2) Sets values for leaf nodes
// (3) Establishes parent-child relationships between levels

func (t *MemTree) Construct(values [][]byte) {
	if !t.Empty() {
		// MemTree should be empty
		panic("MemTree is not empty")
	}
	var count int
	if count = len(values); count == 0 {
		panic("No values")
	}
	height := calcMemTreeHeight(count)
	t.levels = make([]Level, height)
	height--
	t.levels[height] = make(Level, count)
	hasher := ripemd160.New()
	Printf("There are %d leaves\n", len(values))
	for i, value := range values {
		hasher.Write(value)
		hash := hasher.Sum(nil)
		t.levels[height][i] = &Node{hash: hash}
		hasher.Reset()
	}
	for height > 0 {
		children := t.levels[height]
		height--
		t.levels[height] = constructLevel(children)
		Printf("Level %d has %d nodes\n", height, len(t.levels[height]))
	}
}

func constructLevel(children Level) Level {
	numChildren := len(children)
	size := (numChildren + (numChildren & 1)) >> 1
	parents := make(Level, size)
	for i := 0; i < size; i++ {
		nd := new(Node)
		left := children[2*i]
		nd.left = left
		left.parent = nd
		if 2*i+1 < len(children) {
			right := children[2*i+1]
			nd.right = right
			right.parent = nd
		}
		parents[i] = nd
	}
	return parents
}

func calcMemTreeHeight(count int) int {
	switch {
	case count == 0:
		return 0
	case count == 1:
		return 2
	default:
		var i, log int = count, 0
		for {
			if i >>= 1; i == 0 {
				break
			}
			log++
		}
		if count != 0 {
			if (count & (count - 1)) == 0 {
				return log + 1
			}
		}
		return log + 2
	}
}

// DFS traversal and hashing of non-leaf nodes

func (t *MemTree) HashLevels() []byte {
	root := t.Root()
	nd := root
	var hash []byte
	hasher := ripemd160.New()
	for {
		if nd.hash != nil {
			if nd == root {
				return nd.hash
			}
			nd = nd.parent
			continue
		}
		if nd.IsLeaf() {
			panic("Leaf does not have value")
		}
		if nd.left.hash == nil {
			nd = nd.left
			continue
		}
		hash = nd.left.hash
		if nd.right != nil {
			if nd.right.hash == nil {
				nd = nd.right
				continue
			}
			hash = append(hash, nd.right.hash...)
		}
		hasher.Write(hash)
		nd.hash = hasher.Sum(nil)
		hasher.Reset()
		if nd == root {
			return nd.hash
		}
		nd = nd.parent
	}
}
