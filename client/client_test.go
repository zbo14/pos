package client

import (
	// "fmt"
	"github.com/zballs/pos/chain"
	"testing"
)

const (
	id   = 0
	path = "test_chain"
)

func TestClient(t *testing.T) {
	// Create new client
	cli := NewClient(path)
	// Init client
	if err := cli.Init(id); err != nil {
		t.Error(err.Error())
	}
	// Mine space proof
	spaceProof := cli.MineSpace()
	// Mine commit proof
	commitProof := cli.MineCommit()
	priv := cli.Prover.Priv
	// Create genesis block
	genesis := chain.GenesisBlock(commitProof, priv, spaceProof, cli.Txs)
	// Write genesis block to chain
	if err := cli.Chain.Write(genesis); err != nil {
		t.Error(err.Error())
	}
	// Generate new block in round
	cli.Round()
}
