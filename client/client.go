package client

import (
	"github.com/tendermint/go-crypto"
	"github.com/zballs/pos/chain"
	"github.com/zballs/pos/crypto/tndr"
	"github.com/zballs/pos/p2p"
	proto "github.com/zballs/pos/protocol"
	. "github.com/zballs/pos/util"
	"time"
)

const (
	DELTA   = 50
	TIMEOUT = 10 * time.Second
)

type Client struct {
	blocks   chan *chain.Block
	Chain    *chain.Chain
	Delta    int
	Node     *p2p.Node
	Prover   *proto.Prover
	seed     []byte
	Txs      []*chain.Tx
	Verifier *proto.Verifier
}

func Configure(priv crypto.PrivKeyEd25519) {
	p2p.NewConfig("", "", "", "", "", priv, "", 0)
}

func NewClient(chainPath, password string) *Client {
	chain := chain.NewChain(chainPath)
	priv := tndr.GeneratePrivKey(password)
	Configure(priv)
	prover := proto.NewProver(priv)
	verifier := proto.NewVerifier()
	return &Client{
		Chain:    chain,
		Delta:    DELTA,
		Prover:   prover,
		Verifier: verifier,
	}
}

func (cli *Client) Init(configPath string, id int) {
	if cli.Prover == nil {
		panic("Prover is not set")
	}
	// Set merkle tree
	cli.Prover.MerkleTree(id)
	// Construct graph -- defaults to stacked expander
	// TODO: add modularity
	cli.Prover.GraphStackedExpanders(id)
	// Commit
	// (1) Set graph values
	// (2) Add leaves to merkle tree
	// (3) Hash levels of merkle tree
	// (4) Set commit to root hash
	cli.Prover.MakeCommit()
	// Create TxCommit
	commit := cli.Prover.Commit
	pub := cli.Prover.PubKey()
	txCommit := chain.NewTxCommit(commit, pub, 0) // what should txId be?
	tx := chain.NewTx(txCommit)
	cli.Txs = append(cli.Txs, tx)
	// Run node
	cli.Node = p2p.RunNode(configPath)
}

func (cli *Client) MineCommit() *proto.CommitProof {
	seed := cli.Seed()
	challenges := cli.CommitChallenges(seed)
	commitProof := cli.ProveCommit(challenges)
	commitProof.Seed = cli.seed
	return commitProof
}

func (cli *Client) MineSpace() *proto.SpaceProof {
	seed := cli.Seed()
	challenges := cli.SpaceChallenges(seed)
	spaceProof := cli.ProveSpace(challenges)
	spaceProof.Seed = cli.seed
	return spaceProof
}

func (cli *Client) CommitQuality(commitProof *proto.CommitProof) float64 {
	if err := cli.VerifyCommit(commitProof); err != nil {
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
	if err := cli.VerifySpace(spaceProof); err != nil {
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

// Prover

func (cli *Client) ProveCommit(challenges Int64s) *proto.CommitProof {
	return cli.Prover.ProveCommit(challenges)
}

func (cli *Client) ProveSpace(challenges Int64s) *proto.SpaceProof {
	return cli.Prover.ProveSpace(challenges)
}

func (cli *Client) PrivKey() crypto.PrivKeyEd25519 {
	return cli.Prover.Priv
}

// Verifier

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

func (cli *Client) VerifyCommit(commitProof *proto.CommitProof) error {
	return cli.Verifier.VerifyCommit(commitProof)
}

func (cli *Client) VerifySpace(spaceProof *proto.SpaceProof) error {
	return cli.Verifier.VerifySpace(spaceProof)
}

//..

func (cli *Client) Seed() []byte {
	id := cli.Chain.Last()
	var data []byte //nil
	if id >= 0 {
		if id >= cli.Delta {
			id -= cli.Delta // -1??
		}
		b := cli.Chain.MustRead(id)
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
				// .. send block to peers?
				// .. write block to chain?
				return
			}
		case <-time.After(TIMEOUT):
			break
		}
	}
	// Read last block
	last := cli.Chain.Last()
	lastb := cli.Chain.MustRead(last)
	// Get privkey
	priv := cli.PrivKey()
	// Generate commit proof (if we're creating new block?)
	commitProof := cli.MineCommit()
	// Create new block
	newb := chain.NewBlock(commitProof, lastb, priv, spaceProof, cli.Txs)
	//----- For testing -----//
	cli.Chain.MustWrite(newb)
	// TODO: send new_block to peers in network
}
