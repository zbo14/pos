package pos

import (
	// "fmt"
	"github.com/pkg/errors"
	"github.com/zballs/pos/crypto"
	"github.com/zballs/pos/graph"
	. "github.com/zballs/pos/util"
)

const (
	// Proof types
	CONSISTENCY_PROOF = 0x01
	SPACE_PROOF       = 0x02
)

type Commitment struct {
	Commit    []byte            `json:"commit"`
	PubKey    *crypto.PublicKey `json:"public_key"`
	Signature *crypto.Signature `json:"signature"`
}

type Proof interface {
	IsProofType() byte
}

type ConsistencyProof struct {
	ParentProofs [][]*MerkleProof  `json:"parent_proofs"`
	Proofs       []*MerkleProof    `json:"proofs"`
	PubKey       *crypto.PublicKey `json:"public_key"`
	Size         int64             `json:"size"`
}

type SpaceProof struct {
	Proofs []*MerkleProof    `json:"proofs"`
	PubKey *crypto.PublicKey `json:"public_key"`
	Size   int64             `json:"size"`
}

func (_ *ConsistencyProof) IsProofType() byte { return CONSISTENCY_PROOF }
func (_ *SpaceProof) IsProofType() byte       { return SPACE_PROOF }

// Do we need `space` (i.e. *os.File) if we're
// storing values in the graph+tree leveldbs
// which are on disk? I thinks not

type Prover struct {
	commit []byte //merkle root hash
	graph  *graph.Graph
	priv   *crypto.PrivateKey
	tree   *Tree
}

func NewProver(priv *crypto.PrivateKey) *Prover {
	return &Prover{
		priv: priv,
	}
}

func (p *Prover) MerkleTree(id int) error {
	tree, err := NewTree(id)
	if err != nil {
		return err
	}
	p.tree = tree
	return nil
}

func (p *Prover) GraphDoubleButterfly(id int) error {
	g, err := graph.DefaultDoubleButterfly(id)
	if err != nil {
		return err
	}
	p.graph = g
	return nil
}

func (p *Prover) GraphLinearSuperConcentrator(id int) error {
	g, err := graph.DefaultLinearSuperConcentrator(id)
	if err != nil {
		return err
	}
	p.graph = g
	return nil
}

func (p *Prover) GraphStackedExpanders(id int) error {
	g, err := graph.DefaultStackedExpanders(id)
	if err != nil {
		return err
	}
	p.graph = g
	return nil
}

func (p *Prover) Commit() error {
	pub := p.priv.PublicKey()
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
		return nil, errors.New("Commit is not set")
	}
	pub := p.priv.PublicKey()
	sig := p.priv.Sign(p.commit)
	return &Commitment{
		Commit:    p.commit,
		PubKey:    pub,
		Signature: sig,
	}, nil
}

func (p *Prover) NewConsistencyProof(parentProofs [][]*MerkleProof, proofs []*MerkleProof) *ConsistencyProof {
	return &ConsistencyProof{
		ParentProofs: parentProofs,
		Proofs:       proofs,
		PubKey:       p.priv.PublicKey(),
		Size:         p.graph.Size(),
	}
}

func (p *Prover) ProveConsistency(challenges []int64) (*ConsistencyProof, error) {
	if p.graph == nil { // overkill?
		return nil, errors.New("Graph is not set")
	}
	if p.tree == nil {
		return nil, errors.New("Tree is not set")
	}
	var parents Int64s
	proofs := make([]*MerkleProof, len(challenges))
	parentProofs := make([][]*MerkleProof, len(challenges))
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
			parentProofs[i] = make([]*MerkleProof, len(parents))
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

func (p *Prover) NewSpaceProof(proofs []*MerkleProof) *SpaceProof {
	return &SpaceProof{
		Proofs: proofs,
		PubKey: p.priv.PublicKey(),
		Size:   p.graph.Size(),
	}
}

func (p *Prover) ProveSpace(challenges []int64) (*SpaceProof, error) {
	if p.graph == nil {
		return nil, errors.New("Graph is not set")
	}
	if p.tree == nil {
		return nil, errors.New("Tree is not set")
	}
	proofs := make([]*MerkleProof, len(challenges))
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
