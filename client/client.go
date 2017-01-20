package client

import (
	"fmt"
	"github.com/zballs/pos/chain"
	"github.com/zballs/pos/crypto"
	proto "github.com/zballs/pos/protocol"
	. "github.com/zballs/pos/util"
	"time"
)

const TIMEOUT = 10

type Client struct {
	blocks   chan *chain.Block
	Chain    *chain.Chain
	Delta    int64
	Prover   *proto.Prover
	seed     []byte
	Verifier *proto.Verifier
}

func NewClient(path string, delta int64) *Client {
	chain, err := chain.NewChain(path)
	Check(err)
	priv, _ := crypto.GenerateKeypair()
	prover := proto.NewProver(priv)
	verifier := proto.NewVerifier()
	return &Client{
		Chain:    chain,
		Prover:   prover,
		Verifier: verifier,
	}
}

func (cli *Client) Init(id int) (err error) {
	if cli.Prover == nil {
		return Error("Prover is not set")
	}
	// Set merkle tree
	if err = cli.Prover.MerkleTree(id); err != nil {
		return err
	}
	// Construct graph -- defaults to stacked expander
	// .. should we add modularity here??
	if err = cli.Prover.GraphStackedExpanders(id); err != nil {
		return err
	}
	// Commit
	// (1) Set graph values
	// (2) Add leaves to merkle tree
	// (3) Hash levels of merkle tree
	// (4) Set commit to root hash
	if err = cli.Prover.Commit(); err != nil {
		return err
	}
	return nil
}

func (cli *Client) MineConsistency() *proto.ConsistencyProof {
	seed := cli.Seed()
	challenges, err := cli.Verifier.ConsistencyChallenges(seed)
	Check(err)
	consistency, err := cli.Prover.ProveConsistency(challenges)
	Check(err)
	consistency.Seed = cli.seed
	return consistency
}

func (cli *Client) MineSpace() *proto.SpaceProof {
	seed := cli.Seed()
	challenges, err := cli.Verifier.SpaceChallenges(seed)
	Check(err)
	space, err := cli.Prover.ProveSpace(challenges)
	Check(err)
	space.Seed = cli.seed
	return space
}

func (cli *Client) ConsistencyQuality(consistency *proto.ConsistencyProof) float64 {
	if err := cli.Verifier.VerifyConsistency(consistency); err != nil {
		return 0
	}
	hash := NewHash()
	for _, p := range consistency.Proofs {
		hash.Write(p.Value)
	}
	data := hash.Sum(nil)
	float := BytesToFloat(data)
	graphSize := cli.Verifier.GraphSize()
	num, _ := BigPow(float, graphSize).Float64()
	den := Exp2(float64(1<<8) / float64(graphSize))
	quality := num / den
	return quality
}

func (cli *Client) SpaceQuality(space *proto.SpaceProof) float64 {
	if err := cli.Verifier.VerifySpace(space); err != nil {
		return 0
	}
	hash := NewHash()
	for _, p := range space.Proofs {
		hash.Write(p.Value)
	}
	data := hash.Sum(nil)
	float := BytesToFloat(data)
	graphSize := cli.Verifier.GraphSize()
	num, _ := BigPow(float, graphSize).Float64()
	den := Exp2(float64(1<<8) / float64(graphSize))
	quality := num / den
	return quality
}

func (cli *Client) ConsistencyChallenges(seed []byte) Int64s {
	challenges, err := cli.Verifier.ConsistencyChallenges(seed)
	Check(err)
	return challenges
}

func (cli *Client) SpaceChallenges(seed []byte) Int64s {
	challenges, err := cli.Verifier.SpaceChallenges(seed)
	Check(err)
	return challenges
}

func (cli *Client) Seed() []byte {
	id := cli.Chain.Last()
	if id >= cli.Delta {
		id -= cli.Delta // -1??
	}
	b, err := cli.Chain.Read(int(id))
	Check(err)
	data := b.Serialize()
	cli.seed = Sum64(data)
	return cli.seed
}

func (cli *Client) Round() {
	space := cli.MineSpace()
	quality := cli.SpaceQuality(space)
	for {
		select {
		case b := <-cli.blocks:
			// Check quality
			_space := b.SubHash.SpaceProof
			_quality := cli.SpaceQuality(_space)
			if _quality > quality {
				return
			}
		case <-time.After(time.Second * TIMEOUT):
			break
		}
	}
	last := cli.Chain.Last()
	lastb, err := cli.Chain.Read(int(last))
	Check(err)
	priv := cli.Prover.Priv
	newb := chain.NewBlock(lastb, priv, space, nil) //no txs for now
	fmt.Println(newb)
	// TODO: send new_block to peers in network
}
