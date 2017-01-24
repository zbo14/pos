package protocol

import (
	"github.com/tendermint/go-crypto"
	"github.com/zballs/pos/crypto/tndr"
	"github.com/zballs/pos/graph"
	"github.com/zballs/pos/merkle"
	. "github.com/zballs/pos/util"
)

type CommitProof struct {
	ParentProofs [][]*merkle.Proof    `json:"parent_proofs"`
	Proofs       []*merkle.Proof      `json:"proofs"`
	PubKey       crypto.PubKeyEd25519 `json:"public_key"`
	Seed         []byte               `json:"seed"`
	Size         int64                `json:"size"`
}

type SpaceProof struct {
	Proofs []*merkle.Proof      `json:"proofs"`
	PubKey crypto.PubKeyEd25519 `json:"public_key"`
	Seed   []byte               `json:"seed"`
	Size   int64                `json:"size"`
}

// Do we need `space` (i.e. *os.File) if we're
// storing values in the graph+tree leveldbs
// which are on disk? I thinks not

type Prover struct {
	Commit []byte //merkle root hash
	graph  *graph.Graph
	Priv   crypto.PrivKeyEd25519
	tree   *merkle.Tree
}

func NewProver(priv crypto.PrivKeyEd25519) *Prover {
	return &Prover{
		Priv: priv,
	}
}

func (p *Prover) PubKey() crypto.PubKeyEd25519 {
	return tndr.PubKey(p.Priv)
}

func (p *Prover) MerkleTree(id int) {
	p.tree = merkle.NewTree(id)
}

func (p *Prover) Graph(id int, _type string) {
	switch _type {
	case graph.DOUBLE_BUTTERFLY:
		p.graph = graph.DefaultDoubleButterfly(id)
	case graph.LINEAR_SUPER_CONCENTRATOR:
		p.graph = graph.DefaultLinearSuperConcentrator(id)
	case graph.STACKED_EXPANDERS:
		p.graph = graph.DefaultStackedExpanders(id)
	default:
		Panicf("Unexpected graph type: %s\n", _type)
	}
}

func (p *Prover) GraphDoubleButterfly(id int) {
	p.Graph(id, graph.DOUBLE_BUTTERFLY)
}

func (p *Prover) GraphLinearSuperConcentrator(id int) {
	p.Graph(id, graph.LINEAR_SUPER_CONCENTRATOR)
}

func (p *Prover) GraphStackedExpanders(id int) {
	p.Graph(id, graph.STACKED_EXPANDERS)
}

func (p *Prover) MakeCommit() {
	pub := p.PubKey()
	p.graph.SetValues(pub)
	numLeaves := p.graph.Size()
	p.tree.Init(numLeaves)
	var idx int64
	for ; idx < numLeaves; idx++ {
		nd := p.graph.Get(idx)
		if !p.tree.AddLeaf(nd.Value) {
			panic("Could not add leaf")
		}
	}
	p.tree.HashLevels()
	p.Commit = p.tree.Root()
}

func (p *Prover) NewCommitProof(parentProofs [][]*merkle.Proof, proofs []*merkle.Proof) *CommitProof {
	pub := p.PubKey()
	size := p.graph.Size()
	return &CommitProof{
		ParentProofs: parentProofs,
		Proofs:       proofs,
		PubKey:       pub,
		Size:         size,
	}
}

func (p *Prover) ProveCommit(challenges []int64) *CommitProof {
	if p.graph == nil {
		panic("Graph is not set")
	}
	if p.tree == nil {
		panic("Tree is not set")
	}
	var parents Int64s
	proofs := make([]*merkle.Proof, len(challenges))
	parentProofs := make([][]*merkle.Proof, len(challenges))
	for i, c := range challenges {
		sibling := p.graph.Get(c ^ 1)
		nd := p.graph.Get(c)
		proofs[i] = p.tree.ComputeProof(c, sibling.Value, nd.Value)
		parents = p.graph.GetParents(c)
		if len(parents) > 0 {
			parentProofs[i] = make([]*merkle.Proof, len(parents))
			for j, parent := range parents { //should be sorted
				sibling = p.graph.Get(parent ^ 1)
				nd = p.graph.Get(parent)
				parentProofs[i][j] = p.tree.ComputeProof(parent, sibling.Value, nd.Value)
			}
		}
	}
	return p.NewCommitProof(parentProofs, proofs)
}

func (p *Prover) NewSpaceProof(proofs []*merkle.Proof) *SpaceProof {
	pub := p.PubKey()
	size := p.graph.Size()
	return &SpaceProof{
		Proofs: proofs,
		PubKey: pub,
		Size:   size,
	}
}

func (p *Prover) ProveSpace(challenges []int64) *SpaceProof {
	if p.graph == nil {
		panic("Graph is not set")
	}
	if p.tree == nil {
		panic("Tree is not set")
	}
	proofs := make([]*merkle.Proof, len(challenges))
	for i, c := range challenges {
		sibling := p.graph.Get(c ^ 1)
		nd := p.graph.Get(c)
		proofs[i] = p.tree.ComputeProof(c, sibling.Value, nd.Value)
	}
	return p.NewSpaceProof(proofs)
}
