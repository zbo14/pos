package protocol

import (
	"github.com/zballs/pos/crypto"
	"github.com/zballs/pos/graph"
	"github.com/zballs/pos/merkle"
	. "github.com/zballs/pos/util"
)

type Commitment struct {
	Commit    []byte            `json:"commit"`
	PubKey    *crypto.PublicKey `json:"public_key"`
	Signature *crypto.Signature `json:"signature"`
}

type ConsistencyProof struct {
	ParentProofs [][]*merkle.Proof `json:"parent_proofs"`
	Proofs       []*merkle.Proof   `json:"proofs"`
	PubKey       *crypto.PublicKey `json:"public_key"`
	Seed         []byte            `json:"seed"`
	Size         int64             `json:"size"`
}

type SpaceProof struct {
	Proofs []*merkle.Proof   `json:"proofs"`
	PubKey *crypto.PublicKey `json:"public_key"`
	Seed   []byte            `json:"seed"`
	Size   int64             `json:"size"`
}

// Do we need `space` (i.e. *os.File) if we're
// storing values in the graph+tree leveldbs
// which are on disk? I thinks not

type Prover struct {
	commit []byte //merkle root hash
	graph  *graph.Graph
	Priv   *crypto.PrivateKey
	tree   *merkle.Tree
}

func NewProver(priv *crypto.PrivateKey) *Prover {
	return &Prover{
		Priv: priv,
	}
}

func (p *Prover) MerkleTree(id int) error {
	tree, err := merkle.NewTree(id)
	if err != nil {
		return err
	}
	p.tree = tree
	return nil
}

func (p *Prover) Graph(id int, _type string) (err error) {
	switch _type {
	case graph.DOUBLE_BUTTERFLY:
		p.graph, err = graph.DefaultDoubleButterfly(id)
	case graph.LINEAR_SUPER_CONCENTRATOR:
		p.graph, err = graph.DefaultLinearSuperConcentrator(id)
	case graph.STACKED_EXPANDERS:
		p.graph, err = graph.DefaultStackedExpanders(id)
	default:
		return Errorf("Unexpected graph type: %s\n", _type)
	}
	if err != nil {
		p.graph = nil
		return err
	}
	return nil
}

func (p *Prover) GraphDoubleButterfly(id int) error {
	return p.Graph(id, graph.DOUBLE_BUTTERFLY)
}

func (p *Prover) GraphLinearSuperConcentrator(id int) error {
	return p.Graph(id, graph.LINEAR_SUPER_CONCENTRATOR)
}

func (p *Prover) GraphStackedExpanders(id int) error {
	return p.Graph(id, graph.STACKED_EXPANDERS)
}

func (p *Prover) Commit() error {
	pub := p.Priv.Public()
	if err := p.graph.SetValues(pub); err != nil {
		return err
	}
	numLeaves := p.graph.Size()
	p.tree.Init(numLeaves)
	var idx int64
	for ; idx < numLeaves; idx++ {
		nd, err := p.graph.Get(idx)
		if err != nil {
			return err
		} else if len(nd.Value) == 0 {
			//..
		}
		if err = p.tree.AddLeaf(nd.Value); err != nil {
			return err
		}
	}
	if err := p.tree.HashLevels(); err != nil {
		return err
	}
	commit, err := p.tree.Root()
	if err != nil {
		return err
	}
	p.commit = commit
	return nil
}

func (p *Prover) MakeCommitment() (*Commitment, error) {
	if len(p.commit) == 0 {
		return nil, Error("Commit is not set")
	}
	pub := p.Priv.Public()
	sig := p.Priv.Sign(p.commit)
	return &Commitment{
		Commit:    p.commit,
		PubKey:    pub,
		Signature: sig,
	}, nil
}

func (p *Prover) NewConsistencyProof(parentProofs [][]*merkle.Proof, proofs []*merkle.Proof) *ConsistencyProof {
	return &ConsistencyProof{
		ParentProofs: parentProofs,
		Proofs:       proofs,
		PubKey:       p.Priv.Public(),
		Size:         p.graph.Size(),
	}
}

func (p *Prover) ProveConsistency(challenges []int64) (*ConsistencyProof, error) {
	if p.graph == nil { // overkill?
		return nil, Error("Graph is not set")
	}
	if p.tree == nil {
		return nil, Error("Tree is not set")
	}
	var parents Int64s
	proofs := make([]*merkle.Proof, len(challenges))
	parentProofs := make([][]*merkle.Proof, len(challenges))
	for i, c := range challenges {
		sibling, err := p.graph.Get(c ^ 1)
		if err != nil {
			return nil, err
		}
		nd, err := p.graph.Get(c)
		if err != nil {
			return nil, err
		}
		proofs[i], err = p.tree.ComputeProof(c, sibling.Value, nd.Value)
		if err != nil {
			return nil, err
		}
		parents, err = p.graph.GetParents(c)
		if err != nil {
			return nil, err
		}
		if len(parents) > 0 {
			parentProofs[i] = make([]*merkle.Proof, len(parents))
			for j, parent := range parents { //should be sorted
				sibling, err = p.graph.Get(parent ^ 1)
				if err != nil {
					return nil, err
				}
				nd, err = p.graph.Get(parent)
				if err != nil {
					return nil, err
				}
				parentProofs[i][j], err = p.tree.ComputeProof(parent, sibling.Value, nd.Value)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	commitmentProof := p.NewConsistencyProof(parentProofs, proofs)
	return commitmentProof, nil
}

func (p *Prover) NewSpaceProof(proofs []*merkle.Proof) *SpaceProof {
	return &SpaceProof{
		Proofs: proofs,
		PubKey: p.Priv.Public(),
		Size:   p.graph.Size(),
	}
}

func (p *Prover) ProveSpace(challenges []int64) (*SpaceProof, error) {
	if p.graph == nil {
		return nil, Error("Graph is not set")
	}
	if p.tree == nil {
		return nil, Error("Tree is not set")
	}
	proofs := make([]*merkle.Proof, len(challenges))
	for i, c := range challenges {
		sibling, err := p.graph.Get(c ^ 1)
		if err != nil {
			return nil, err
		}
		nd, err := p.graph.Get(c)
		if err != nil {
			return nil, err
		}
		proofs[i], err = p.tree.ComputeProof(c, sibling.Value, nd.Value)
		if err != nil {
			return nil, err
		}
	}
	spaceProof := p.NewSpaceProof(proofs)
	return spaceProof, nil
}
