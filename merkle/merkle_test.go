package merkle

import (
	"testing"
)

var values = [][]byte{
	[]byte("abc"),
	[]byte("xyz"),
	[]byte("hello world"),
	[]byte("deadbeef"),
	[]byte("foobar"),
	[]byte("foobaz"),
	[]byte("testing testing.."),
	[]byte("merkle derp"),
	[]byte("number 9"),
}

func TestMerkle(t *testing.T) {
	tree := new(MemTree)
	if err := tree.Construct(values); err != nil {
		t.Fatal(err.Error())
	}
	rootHash, err := tree.HashLevels()
	if err != nil {
		t.Fatal(err.Error())
	}
	proof, err := tree.ComputeMemProof(7)
	if err != nil {
		t.Fatal(err.Error())
	}
	if !VerifyMemProof(proof, rootHash) {
		t.Error("MemProof verification failed")
	}
}
