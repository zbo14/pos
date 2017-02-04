package graph

import (
	"github.com/syndtr/goleveldb/leveldb"
	// "github.com/zbo14/pos/crypto"
	"github.com/tendermint/go-crypto"
	. "github.com/zbo14/pos/util"
	"path/filepath"
	"sort"
	"strconv"
)

const (
	// Graph types
	DOUBLE_BUTTERFLY          = "double_butterfly"
	LINEAR_SUPER_CONCENTRATOR = "linear_super_concentrator"
	STACKED_EXPANDERS         = "stacked_expanders"
)

type GraphType interface {
	IsGraphType() string
}

type Graph struct {
	batch *leveldb.Batch
	db    *leveldb.DB
	impl  GraphType
	size  int64
}

func NewGraph(id int, size int64, _type string) *Graph {
	switch _type {
	case DOUBLE_BUTTERFLY,
		LINEAR_SUPER_CONCENTRATOR,
		STACKED_EXPANDERS:
	default:
		panic("Invalid graph type: " + _type)
	}
	var err error
	g := new(Graph)
	path := filepath.Join("Graph", _type, strconv.Itoa(id))
	g.batch = new(leveldb.Batch) //necessary?
	g.db, err = leveldb.OpenFile(path, nil)
	Check(err)
	g.size = size
	return g
}

func (g *Graph) Size() int64 {
	return g.size
}

func (g *Graph) SetType(impl GraphType) bool {
	if g.impl != nil {
		return false
	}
	g.impl = impl
	return true
}

// Get node
func (g *Graph) Get(idx int64) *Node {
	if idx < 0 {
		panic("Idx cannot be less than 0")
	} else if idx >= g.size {
		Panicf("Expected idx < %d; got idx=%d\n", g.size, idx)
	}
	key := Int64Bytes(idx)
	data, err := g.db.Get(key, nil)
	Check(err)
	nd := new(Node)
	err = nd.UnmarshalBinary(data)
	Check(err)
	if nd.Idx != idx {
		Panicf("Expected node with idx=%d; got idx=%d\n", idx, nd.Idx)
	}
	return nd
}

func (g *Graph) put(nd *Node) {
	data, _ := nd.MarshalBinary()
	key := Int64Bytes(nd.Idx)
	err := g.db.Put(key, data, nil)
	Check(err)
}

func (g *Graph) putBatch(nd *Node) {
	data, _ := nd.MarshalBinary()
	key := Int64Bytes(nd.Idx)
	g.batch.Put(key, data)
}

func (g *Graph) writeBatch() {
	err := g.db.Write(g.batch, nil)
	Check(err)
	g.batch = new(leveldb.Batch)
}

// Initialize node values
// value = hash(pubKey_bytes, idx, [parent1.Value, parent2.Value, ...])

func (g *Graph) SetValues(pub crypto.PubKeyEd25519) {
	hash := NewHash()
	pkbz := pub.Bytes()
	var idx int64
	for ; idx < g.size; idx++ {
		nd := g.Get(idx)
		bz := append(pkbz, Int64Bytes(idx)...)
		if !nd.NoParents() {
			sort.Sort(nd.Parents)
			for _, p := range nd.Parents {
				parent := g.Get(p)
				if parent.Value == nil {
					Panicf("Cannot set value for idx=%d; parent idx=%d does not have value", nd.Idx, parent.Idx)
				}
				bz = append(bz, parent.Value...)
			}
		}
		hash.Reset()
		hash.Write(bz)
		nd.Value = hash.Sum(nil)
		g.put(nd)
	}
}

func (g *Graph) GetParents(idx int64) Int64s {
	nd := g.Get(idx)
	return nd.Parents
}

func (g *Graph) Print() {
	var idx int64
	for ; idx < g.size; idx++ {
		nd := g.Get(idx)
		Println(nd)
	}
}
