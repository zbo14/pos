package pos

import (
	"github.com/zballs/pos/crypto"
	"testing"
)

func TestPos(t *testing.T) {
	// Create prover with private key
	priv := crypto.GeneratePrivateKey()
	prover := NewProver(priv)
	// Initialize merkle tree
	if err := prover.MerkleTree(0); err != nil {
		t.Error(err.Error())
	}
	// Construct graph
	//prover.GraphDoubleButterfly
	//prover.GraphLinearSuperconcentrator
	if err := prover.GraphStackedExpanders(0); err != nil {
		t.Error(err.Error())
	}
	// Commit
	// (1) Set graph values
	// (2) Add leaves to merkle tree
	// (3) Hash levels of merkle tree
	// (4) Set commit to root hash
	if err := prover.Commit(); err != nil {
		t.Error(err.Error())
	}
	// Make commitment (commit, public_key, signature)
	cmt, err := prover.MakeCommitment()
	if err != nil {
		t.Error(err.Error())
	}
	// Create verifier
	verifier, _ := NewVerifier(prover.graph.Size()) // size should be agreed upon parameter
	if err := verifier.VerifyCommitment(cmt); err != nil {
		t.Error(err.Error())
	}
	// Randomly sample commit challenges
	challenges, err := verifier.CommitChallenges()
	if err != nil {
		t.Error(err.Error())
	}
	// Generate commit proof
	commitProof, err := prover.ProveCommit(challenges)
	if err != nil {
		t.Error(err.Error())
	}
	// Verify commit proof
	if err := verifier.VerifyCommit(commitProof); err != nil {
		t.Error(err.Error())
	}
	// Randomly sample space challenges
	challenges, err = verifier.SpaceChallenges()
	if err != nil {
		t.Error(err.Error())
	}
	// Generate space proof
	spaceProof, err := prover.ProveSpace(challenges)
	if err != nil {
		t.Error(err.Error())
	}
	// Verify space proof
	if err := verifier.VerifySpace(spaceProof); err != nil {
		t.Error(err.Error())
	}
}
