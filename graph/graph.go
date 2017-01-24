package graph

import (
	"github.com/syndtr/goleveldb/leveldb"
	// "github.com/zballs/pos/crypto"
	"github.com/tendermint/go-crypto"
	. "github.com/zballs/pos/util"
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

func NewGraph(id int, size int64, _type string) (g *Graph, err error) {
	switch _type {
	case DOUBLE_BUTTERFLY,
		LINEAR_SUPER_CONCENTRATOR,
		STACKED_EXPANDERS:
	default:
		return nil, Error("Invalid graph type")
	}
	path := filepath.Join("Graph", _type, strconv.Itoa(id))
	g = new(Graph)
	g.batch = new(leveldb.Batch) //necessary?
	g.db, err = leveldb.OpenFile(path, nil)
	if err != nil {
		return nil, err
	}
	g.size = size
	return g, nil
}

func (g *Graph) Size() int64 {
	return g.size
}

func (g *Graph) SetType(impl GraphType) error {
	if g.impl != nil {
		return Error("Graph type already set")
	}
	g.impl = impl
	return nil
}

// Get node
func (g *Graph) Get(idx int64) (*Node, error) {
	if idx < 0 {
		return nil, Error("Idx cannot be less than 0")
	} else if idx >= g.size {
		return nil, Errorf("Expected idx < %d; got idx=%d\n", g.size, idx)
	}
	key := Int64Bytes(idx)
	data, err := g.db.Get(key, nil)
	if err != nil {
		return nil, err
	}
	nd := new(Node)
	if err = nd.UnmarshalBinary(data); err != nil {
		return nil, err
	} else if nd.Idx != idx {
		return nil, Error("Node has incorrect idx")
	}
	return nd, nil
}

func (g *Graph) put(nd *Node) error {
	data, _ := nd.MarshalBinary()
	key := Int64Bytes(nd.Idx)
	if err := g.db.Put(key, data, nil); err != nil {
		return err
	}
	return nil
}

func (g *Graph) putBatch(nd *Node) {
	data, _ := nd.MarshalBinary()
	key := Int64Bytes(nd.Idx)
	g.batch.Put(key, data)
}

func (g *Graph) writeBatch() error {
	if err := g.db.Write(g.batch, nil); err != nil {
		// reset batch?
		return err
	}
	g.batch = new(leveldb.Batch)
	return nil
}

// Initialize node values
// value = hash(pubKey_bytes, idx, [parent1.Value, parent2.Value, ...])

func (g *Graph) SetValues(pub crypto.PubKeyEd25519) error {
	hash := NewHash()
	pkbz := pub.Bytes()
	var idx int64
	for ; idx < g.size; idx++ {
		nd, err := g.Get(idx)
		if err != nil {
			return err
		}
		bz := append(pkbz, Int64Bytes(idx)...)
		if !nd.NoParents() {
			sort.Sort(nd.Parents)
			for _, p := range nd.Parents {
				parent, err := g.Get(p)
				if err != nil {
					return err
				} else if len(parent.Value) == 0 {
					return Errorf("Cannot set value for idx=%d; parent idx=%d does not have value", nd.Idx, parent.Idx)
				}
				bz = append(bz, parent.Value...)
			}
		}
		hash.Reset()
		hash.Write(bz)
		nd.Value = hash.Sum(nil)
		if err = g.put(nd); err != nil {
			return err
		}
	}
	return nil
}

func (g *Graph) GetParents(idx int64) (Int64s, error) {
	nd, err := g.Get(idx)
	if err != nil {
		return nil, err
	}
	return nd.Parents, nil
}

func (g *Graph) Print() {
	var idx int64
	for ; idx < g.size; idx++ {
		nd, _ := g.Get(idx)
		Println(nd)
	}
}
