package client

import (
	"github.com/zbo14/pos/chain"
	. "github.com/zbo14/pos/util"
	"testing"
)

const (
	ID          = 0
	CHAIN_PATH  = "test_chain"
	CONFIG_PATH = ""
	PASSWORD    = "it's a secret"
)

func TestClient(t *testing.T) {
	// Create new client
	cli := NewClient(CHAIN_PATH, PASSWORD)
	// Init client
	cli.Init(CONFIG_PATH, ID)
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
