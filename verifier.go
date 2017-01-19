package pos

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	// "fmt"
	"github.com/pkg/errors"
	"github.com/zballs/pos/crypto"
	. "github.com/zballs/pos/util"
)

const (
	ALPHA_MULT = 1
	BETA_MULT  = 1
	SEED_SIZE  = 64
)

type Verifier struct {
	alpha, beta int
	challenges  Int64s
	commit      []byte
	pub         *crypto.PublicKey
	size        int64
}

func NewVerifier(size int64) (*Verifier, error) {
	alpha := int(Log2(size)) * ALPHA_MULT
	beta := int(Log2(size)) * BETA_MULT
	return &Verifier{
		alpha: alpha,
		beta:  beta,
		size:  size,
	}, nil
}

// (1)

func (v *Verifier) VerifyCommitment(c *Commitment) error {
	if len(c.Commit) != HASH_SIZE {
		return errors.New("Incorrect commit length")
	}
	verified := c.PubKey.Verify(c.Commit, NewHash(), c.Signature)
	if !verified {
		return errors.New("Commitment verification failed")
	}
	v.commit = c.Commit
	v.pub = c.PubKey
	return nil
}

func (v *Verifier) ConsistencyChallenges() (Int64s, error) {
	seed := make([]byte, SEED_SIZE)
	n, err := rand.Read(seed)
	if err != nil {
		return nil, err
	} else if n != SEED_SIZE {
		return nil, errors.New("Could not read entire seed")
	}
	return v.SampleChallenges(seed, v.alpha)
}

func (v *Verifier) SpaceChallenges() (Int64s, error) {
	seed := make([]byte, SEED_SIZE)
	n, err := rand.Read(seed)
	if err != nil {
		return nil, err
	} else if n != SEED_SIZE {
		return nil, errors.New("Could not read entire seed")
	}
	return v.SampleChallenges(seed, v.beta)
}

func (v *Verifier) SampleChallenges(seed []byte, param int) (Int64s, error) {
	challenges := make(Int64s, param)
	rands := make([]byte, param*8)
	Shake(rands, seed)
	for i, _ := range challenges {
		rand, read := binary.Varint(rands[i*8 : (i+1)*8])
		if read < 0 {
			return nil, errors.New("Could not read rand")
		}
		if rand < 0 {
			rand *= -1
		}
		challenges[i] = rand % v.size
	}
	v.challenges = challenges
	return challenges, nil
}

// (2)

func (v *Verifier) VerifyConsistency(consistency *ConsistencyProof) error {
	if len(consistency.Proofs) != v.alpha {
		return errors.New("Incorrect number of proofs")
	} else if len(consistency.ParentProofs) != v.alpha {
		return errors.New("Incorrect number of parent proofs")
	}
	hash := NewHash()
	pkbz, _ := v.pub.MarshalBinary()
	for i, c := range v.challenges {
		value := append(pkbz, Int64Bytes(c)...)
		proof := consistency.Proofs[i]
		if proof.Idx != c {
			return errors.New("Proof has incorrect idx")
		} else if !VerifyProof(proof, v.commit) {
			return errors.New("Proof verification failed")
		}
		for _, p := range consistency.ParentProofs[i] {
			if p.Idx >= c {
				return errors.New("Parent proof has invalid idx")
			} else if !VerifyProof(p, v.commit) {
				return errors.New("Parent proof verification failed")
			}
			value = append(value, p.Value...)
		}
		hash.Reset()
		hash.Write(value)
		value = hash.Sum(nil)
		if !bytes.Equal(proof.Value, value) {
			return errors.New("Proof has incorrect value")
		}
	}
	return nil
}

// (3)

func (v *Verifier) VerifySpace(space *SpaceProof) error {
	if len(space.Proofs) != v.beta {
		return errors.New("Incorrect number of proofs")
	}
	for i, c := range v.challenges {
		proof := space.Proofs[i]
		if proof.Idx != c {
			return errors.New("Proof has incorrect idx")
		} else if !VerifyProof(proof, v.commit) {
			return errors.New("Proof verification failed")
		}
	}
	return nil
}
