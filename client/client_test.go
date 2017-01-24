package client

import (
	"github.com/zballs/pos/chain"
	. "github.com/zballs/pos/util"
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
		t.Fatal(err.Error())
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
		t.Fatal(err.Error())
	}
	// Generate new block in round
	cli.Round()
	// Read most recent block from chain
	lastb := cli.Chain.Last()
	block, err := cli.Chain.Read(lastb)
	if err != nil {
		t.Fatal(err.Error())
	}
	Println(string(MarshalJSON(block)))
}
