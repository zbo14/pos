package graph

import (
	"bytes"
	"github.com/zbo14/pos/crypto"
	. "github.com/zbo14/pos/util"
	"testing"
)

var graph_fn = DefaultStackedExpanders

const IDX = 10

func TestGraph(t *testing.T) {
	// Generate keys
	priv := crypto.GeneratePrivKey()
	pub := priv.PubKey()
	// Construct GraphType
	g, err := graph_fn(0)
	if err != nil {
		t.Error(err.Error())
	}
	// Print nodes
	// g.Print()
	// Set values
	if err = g.SetValues(pub); err != nil {
		t.Error(err.Error())
	}
	// Query a node
	nd, err := g.Get(IDX)
	if err != nil {
		t.Error(err.Error())
	}
	parents, err := g.GetParents(IDX)
	if err != nil {
		t.Error(err.Error())
	}
	hash := NewHash()
	pkbz, _ := pub.MarshalBinary()
	data := append(pkbz, Int64Bytes(IDX)...)
	for _, p := range parents {
		parent, err := g.Get(p)
		if err != nil {
			t.Error(err.Error())
		}
		data = append(data, parent.Value...)
	}
	hash.Write(data)
	value := hash.Sum(nil)
	if !bytes.Equal(nd.Value, value) {
		t.Error("Expected node value=%x; got value=%x")
	}
}
