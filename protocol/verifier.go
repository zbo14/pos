package protocol

import (
	"bytes"
	"encoding/binary"
	// "github.com/zballs/pos/crypto/tndr"
	"github.com/tendermint/go-crypto"
	"github.com/zballs/pos/merkle"
	. "github.com/zballs/pos/util"
)

const (
	ALPHA_MULT = 1     // what should these params be?
	BETA_MULT  = 1     // ..
	GRAPH_SIZE = 65536 // ..
	SEED_SIZE  = 64
)

var (
	ErrIncorrectIdx       = Error("Proof has incorrect idx")
	ErrIncorrectNumProofs = Error("Incorrect number of proofs")
	ErrIncorrectSize      = Error("Incorrect size")
	ErrIncorrectValue     = Error("Proof has incorrect value")
	ErrNotVerified        = Error("Proof verification failed")
)

type Verifier struct {
	alpha, beta int
	challenges  Int64s
	commit      []byte
	pub         crypto.PubKeyEd25519
	graphSize   int64
}

func NewVerifier() *Verifier {
	alpha := int(Log2(GRAPH_SIZE)) * ALPHA_MULT
	beta := int(Log2(GRAPH_SIZE)) * BETA_MULT
	return &Verifier{
		alpha:     alpha,
		beta:      beta,
		graphSize: GRAPH_SIZE,
	}
}

func (v *Verifier) GraphSize() int64 {
	return v.graphSize
}

// (1)

func (v *Verifier) ReceiveCommit(commit []byte, pub crypto.PubKeyEd25519) error {
	if size := len(commit); size != HASH_SIZE {
		return ErrIncorrectSize
	}
	v.commit = commit
	v.pub = pub
	return nil
}

func (v *Verifier) CommitChallenges(seed []byte) (Int64s, error) {
	if size := len(seed); size != SEED_SIZE {
		return nil, ErrIncorrectSize
	}
	return v.SampleChallenges(seed, v.alpha), nil
}

func (v *Verifier) SpaceChallenges(seed []byte) (Int64s, error) {
	if size := len(seed); size != SEED_SIZE {
		return nil, ErrIncorrectSize
	}
	return v.SampleChallenges(seed, v.beta), nil
}

func (v *Verifier) SampleChallenges(seed []byte, param int) Int64s {
	challenges := make(Int64s, param)
	rands := make([]byte, param*8)
	Shake32(rands, seed)
	for i, _ := range challenges {
		rand, _ := binary.Varint(rands[i*8 : (i+1)*8])
		if rand < 0 {
			rand *= -1
		}
		challenges[i] = rand % v.graphSize
	}
	v.challenges = challenges
	return challenges
}

// (2)

func (v *Verifier) VerifyCommit(commitProof *CommitProof) error {
	if len(commitProof.Proofs) != v.alpha {
		return ErrIncorrectNumProofs
	} else if len(commitProof.ParentProofs) != v.alpha {
		return ErrIncorrectNumProofs
	}
	hash := NewHash()
	pkbz := v.pub.Bytes()
	for i, c := range v.challenges {
		value := append(pkbz, Int64Bytes(c)...)
		proof := commitProof.Proofs[i]
		if proof.Idx != c {
			return ErrIncorrectIdx
		} else if !merkle.VerifyProof(proof, v.commit) {
			return ErrNotVerified
		}
		for _, p := range commitProof.ParentProofs[i] {
			if p.Idx >= c {
				return ErrIncorrectIdx
			} else if !merkle.VerifyProof(p, v.commit) {
				return ErrNotVerified
			}
			value = append(value, p.Value...)
		}
		hash.Reset()
		hash.Write(value)
		value = hash.Sum(nil)
		if !bytes.Equal(proof.Value, value) {
			return ErrIncorrectValue
		}
	}
	return nil
}

// (3)

func (v *Verifier) VerifySpace(spaceProof *SpaceProof) error {
	if len(spaceProof.Proofs) != v.beta {
		return ErrIncorrectNumProofs
	}
	for i, c := range v.challenges {
		proof := spaceProof.Proofs[i]
		if proof.Idx != c {
			return ErrIncorrectIdx
		} else if !merkle.VerifyProof(proof, v.commit) {
			return ErrNotVerified
		}
	}
	return nil
}
