package pos

import (
	"github.com/zballs/pos/crypto"
	"testing"
)

func TestPos(t *testing.T) {
	priv := crypto.GeneratePrivateKey()
	prover := NewProver(priv)

	if err := prover.MerkleTree(0); err != nil {
		t.Error(err.Error())
	}
	if err := prover.GraphDoubleButterfly(0); err != nil {
		t.Error(err.Error())
	}
	if err := prover.Commit(); err != nil {
		t.Error(err.Error())
	}
	/*
		c, err := prover.MakeCommitment()
		if err != nil {
			t.Error(err.Error())
		}
		verifier, _ := NewVerifier(prover.graph.Size())
		if err := verifier.VerifyCommitment(c); err != nil {
			t.Error(err.Error())
		}
		challenges, err := verifier.ConsistencyChallenges()
		if err != nil {
			t.Error(err.Error())
		}
		_, err = prover.ProveConsistency(challenges)
		if err != nil {
			t.Error(err.Error())
		}
	*/
	idx := int64(130)
	nd, _ := prover.graph.Get(idx)
	sibling, _ := prover.graph.Get(idx ^ 1)
	proof, _ := prover.tree.ComputeProof(idx, sibling.Value, nd.Value)
	root, _ := prover.tree.Root()
	if !VerifyProof(proof, root) {
		t.Error("Invalid proof")
	}
	idx = int64(145)
	nd, _ = prover.graph.Get(idx)
	sibling, _ = prover.graph.Get(idx ^ 1)
	proof, _ = prover.tree.ComputeProof(idx, sibling.Value, nd.Value)
	if !VerifyProof(proof, root) {
		t.Error("Invalid proof")
	}
	/*
		if err := verifier.VerifyConsistency(cProof); err != nil {
			t.Error(err.Error())
		}
	*/
}
