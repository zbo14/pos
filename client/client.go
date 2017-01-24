package client

import (
	"fmt"
	"github.com/zballs/pos/chain"
	"github.com/zballs/pos/crypto"
	proto "github.com/zballs/pos/protocol"
	. "github.com/zballs/pos/util"
	"time"
)

const DELTA = 50
const TIMEOUT = 10 //seconds

type Client struct {
	blocks   chan *chain.Block
	Chain    *chain.Chain
	Delta    int
	Prover   *proto.Prover
	seed     []byte
	Txs      []*chain.Tx
	Verifier *proto.Verifier
}

func NewClient(path string) *Client {
	chain, err := chain.NewChain(path)
	Check(err)
	priv, _ := crypto.GenerateKeypair()
	prover := proto.NewProver(priv)
	verifier := proto.NewVerifier()
	return &Client{
		Chain:    chain,
		Delta:    DELTA,
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
	// TODO: add modularity
	if err = cli.Prover.GraphStackedExpanders(id); err != nil {
		return err
	}
	// Commit
	// (1) Set graph values
	// (2) Add leaves to merkle tree
	// (3) Hash levels of merkle tree
	// (4) Set commit to root hash
	if err = cli.Prover.MakeCommit(); err != nil {
		return err
	}
	commit := cli.Prover.Commit
	pub := cli.Prover.Pub()
	txCommit := chain.NewTxCommit(commit, pub, 0) // what should txId be?
	tx, err := chain.NewTx(txCommit)
	Check(err)
	cli.Txs = append(cli.Txs, tx)
	return nil
}

func (cli *Client) MineCommit() *proto.CommitProof {
	seed := cli.Seed()
	challenges, err := cli.Verifier.CommitChallenges(seed)
	Check(err)
	commitProof, err := cli.Prover.ProveCommit(challenges)
	Check(err)
	commitProof.Seed = cli.seed
	return commitProof
}

func (cli *Client) MineSpace() *proto.SpaceProof {
	seed := cli.Seed()
	challenges, err := cli.Verifier.SpaceChallenges(seed)
	Check(err)
	fmt.Println(challenges)
	spaceProof, err := cli.Prover.ProveSpace(challenges)
	Check(err)
	spaceProof.Seed = cli.seed
	return spaceProof
}

func (cli *Client) CommitQuality(commitProof *proto.CommitProof) float64 {
	if err := cli.Verifier.VerifyCommit(commitProof); err != nil {
		return 0
	}
	hash := NewHash()
	for _, p := range commitProof.Proofs {
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

func (cli *Client) SpaceQuality(spaceProof *proto.SpaceProof) float64 {
	if err := cli.Verifier.VerifySpace(spaceProof); err != nil {
		return 0
	}
	hash := NewHash()
	for _, p := range spaceProof.Proofs {
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

func (cli *Client) CommitChallenges(seed []byte) Int64s {
	challenges, err := cli.Verifier.CommitChallenges(seed)
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
	var data []byte //nil
	if id >= 0 {
		if id >= cli.Delta {
			id -= cli.Delta // -1??
		}
		b, err := cli.Chain.Read(id)
		Check(err)
		data = b.Serialize()
	}
	cli.seed = Sum64(data)
	return cli.seed
}

func (cli *Client) Round() {
	spaceProof := cli.MineSpace()
	quality := cli.SpaceQuality(spaceProof)
	for {
		select {
		case b := <-cli.blocks:
			// Check quality
			_spaceProof := b.SubHash.SpaceProof
			_quality := cli.SpaceQuality(_spaceProof)
			if _quality > quality {
				// .. should we send block to peers?
				// .. should we write block to chain?
				return
			}
		case <-time.After(time.Second * TIMEOUT):
			break
		}
	}
	// Read last block
	last := cli.Chain.Last()
	lastb, err := cli.Chain.Read(last)
	Check(err)
	// Get privkey
	priv := cli.Prover.Priv
	// Generate commit proof (if we're creating new block?)
	commitProof := cli.MineCommit()
	// Create new block
	newb := chain.NewBlock(commitProof, lastb, priv, spaceProof, cli.Txs)
	//----- For testing -----//
	err = cli.Chain.Write(newb)
	Check(err)
	// TODO: send new_block to peers in network
}
