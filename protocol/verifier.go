package protocol

import (
	"bytes"
	"encoding/binary"
	"github.com/zballs/pos/crypto"
	"github.com/zballs/pos/merkle"
	. "github.com/zballs/pos/util"
)

const (
	ALPHA_MULT = 1     // what should these params be?
	BETA_MULT  = 1     // ..
	GRAPH_SIZE = 65536 // ..
	SEED_SIZE  = 64
)

type Verifier struct {
	alpha, beta int
	challenges  Int64s
	commit      []byte
	pub         *crypto.PublicKey
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

func (v *Verifier) VerifyCommitment(c *Commitment) error {
	if len(c.Commit) != HASH_SIZE {
		return Error("Incorrect commit length")
	}
	verified := c.PubKey.Verify(c.Commit, c.Signature)
	if !verified {
		return Error("Commitment verification failed")
	}
	v.commit = c.Commit
	v.pub = c.PubKey
	return nil
}

func (v *Verifier) ConsistencyChallenges(seed []byte) (Int64s, error) {
	if size := len(seed); size != SEED_SIZE {
		return nil, Errorf("Expected seed with size=%d; got size=%d\n", SEED_SIZE, size)
	}
	return v.SampleChallenges(seed, v.alpha)
}

func (v *Verifier) SpaceChallenges(seed []byte) (Int64s, error) {
	if size := len(seed); size != SEED_SIZE {
		return nil, Errorf("Expected seed with size=%d; got size=%d\n", SEED_SIZE, size)
	}
	return v.SampleChallenges(seed, v.beta)
}

func (v *Verifier) SampleChallenges(seed []byte, param int) (Int64s, error) {
	challenges := make(Int64s, param)
	rands := make([]byte, param*8)
	Shake32(rands, seed)
	for i, _ := range challenges {
		rand, read := binary.Varint(rands[i*8 : (i+1)*8])
		if read < 0 {
			return nil, Error("Could not read rand")
		}
		if rand < 0 {
			rand *= -1
		}
		challenges[i] = rand % v.graphSize
	}
	v.challenges = challenges
	return challenges, nil
}

// (2)

func (v *Verifier) VerifyConsistency(consistency *ConsistencyProof) error {
	if len(consistency.Proofs) != v.alpha {
		return Error("Incorrect number of proofs")
	} else if len(consistency.ParentProofs) != v.alpha {
		return Error("Incorrect number of parent proofs")
	}
	hash := NewHash()
	pkbz, _ := v.pub.MarshalBinary()
	for i, c := range v.challenges {
		value := append(pkbz, Int64Bytes(c)...)
		proof := consistency.Proofs[i]
		if proof.Idx != c {
			return Error("Proof has incorrect idx")
		} else if !merkle.VerifyProof(proof, v.commit) {
			return Error("Proof verification failed")
		}
		for _, p := range consistency.ParentProofs[i] {
			if p.Idx >= c {
				return Error("Parent proof has invalid idx")
			} else if !merkle.VerifyProof(p, v.commit) {
				return Error("Parent proof verification failed")
			}
			value = append(value, p.Value...)
		}
		hash.Reset()
		hash.Write(value)
		value = hash.Sum(nil)
		if !bytes.Equal(proof.Value, value) {
			return Error("Proof has incorrect value")
		}
	}
	return nil
}

// (3)

func (v *Verifier) VerifySpace(space *SpaceProof) error {
	if len(space.Proofs) != v.beta {
		return Error("Incorrect number of proofs")
	}
	for i, c := range v.challenges {
		proof := space.Proofs[i]
		if proof.Idx != c {
			return Error("Proof has incorrect idx")
		} else if !merkle.VerifyProof(proof, v.commit) {
			return Error("Proof verification failed")
		}
	}
	return nil
}
