package crypto

import (
	"crypto/rand"
	. "github.com/zbo14/pos/util"
	"golang.org/x/crypto/ed25519"
)

const (
	PRIVKEY_SIZE   = ed25519.PrivateKeySize
	PUBKEY_SIZE    = ed25519.PublicKeySize
	SIGNATURE_SIZE = ed25519.SignatureSize
)

type PublicKey struct {
	data ed25519.PublicKey
}

type PrivateKey struct {
	data ed25519.PrivateKey
}

type Signature struct {
	data []byte
}

func NewPrivateKey(data ed25519.PrivateKey) (*PrivateKey, error) {
	if size := len(data); size != PRIVKEY_SIZE {
		return nil, Errorf("Expected privkey with size=%d; got size=%d\n", PRIVKEY_SIZE, size)
	}
	return &PrivateKey{data}, nil
}

func NewPublicKey(data ed25519.PublicKey) (*PublicKey, error) {
	if size := len(data); size != PUBKEY_SIZE {
		return nil, Errorf("Expected pubkey with size=%d; got size=%d\n", PUBKEY_SIZE, size)
	}
	return &PublicKey{data}, nil
}

func NewSignature(data []byte) (*Signature, error) {
	if size := len(data); size != SIGNATURE_SIZE {
		return nil, Errorf("Expected signature with size=%d; got size=%d\n", SIGNATURE_SIZE, size)
	}
	return &Signature{data}, nil
}

func GenerateKeypair() (*PrivateKey, *PublicKey) {
	pub_data, priv_data, err := ed25519.GenerateKey(rand.Reader)
	Check(err)
	priv, err := NewPrivateKey(priv_data)
	Check(err)
	pub, err := NewPublicKey(pub_data)
	Check(err)
	return priv, pub
}

// Private Key

func (priv *PrivateKey) Sign(message []byte) *Signature {
	data := ed25519.Sign(priv.data, message)
	sig, err := NewSignature(data)
	Check(err)
	return sig
}

func (priv *PrivateKey) Public() *PublicKey {
	data := priv.data.Public().(ed25519.PublicKey)
	pub, err := NewPublicKey(data)
	Check(err)
	return pub
}

// Public Key

func (pub *PublicKey) Verify(message []byte, sig *Signature) bool {
	return ed25519.Verify(pub.data, message, sig.data)
}

func (pub *PublicKey) Bytes() []byte {
	return pub.data[:]
}

func (pub *PublicKey) MarshalJSON() ([]byte, error) {
	data := MarshalJSON(pub.Bytes())
	return data, nil
}

func (pub *PublicKey) UnmarshalJSON(data []byte) (err error) {
	UnmarshalJSON(data, &pub.data)
	if size := len(pub.data); size != PUBKEY_SIZE {
		return Errorf("Expected pubkey with size=%d; got size=%d\n", PUBKEY_SIZE, size)
	}
	return nil
}

// Signature

func (sig *Signature) Bytes() []byte {
	return sig.data[:]
}

func (sig *Signature) MarshalJSON() ([]byte, error) {
	data := MarshalJSON(sig.Bytes())
	return data, nil
}

func (sig *Signature) UnmarshalJSON(data []byte) (err error) {
	UnmarshalJSON(data, &sig.data)
	if size := len(sig.data); size != SIGNATURE_SIZE {
		return Errorf("Expected signature with size=%d; got size=%d\n", SIGNATURE_SIZE, size)
	}
	return nil
}
