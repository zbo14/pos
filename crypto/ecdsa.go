package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"github.com/pkg/errors"
	. "github.com/zballs/pos/util"
	"hash"
	"math/big"
)

var curve = elliptic.P256()

type PublicKey struct {
	key ecdsa.PublicKey
}

func NewPublicKey(key ecdsa.PublicKey) *PublicKey {
	return &PublicKey{key}
}

type PrivateKey struct {
	key ecdsa.PrivateKey
}

func NewPrivateKey(key ecdsa.PrivateKey) *PrivateKey {
	return &PrivateKey{key}
}

type Signature struct {
	r, s *big.Int
}

func NewSignature(r, s *big.Int) *Signature {
	return &Signature{r, s}
}

func GeneratePrivateKey() *PrivateKey {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	Check(err)
	priv := NewPrivateKey(*key)
	return priv
}

// PrivateKey

func (priv *PrivateKey) PublicKey() *PublicKey {
	key := priv.key.PublicKey
	return NewPublicKey(key)
}

func (priv *PrivateKey) MarshalBinary() ([]byte, error) {
	xbz := priv.key.X.Bytes()
	ybz := priv.key.Y.Bytes()
	dbz := priv.key.D.Bytes()
	xsize := int64(binary.Size(xbz))
	ysize := int64(binary.Size(ybz))
	dsize := int64(binary.Size(dbz))
	buf := new(bytes.Buffer)
	buf.Write(Int64Bytes(xsize))
	buf.Write(xbz)
	buf.Write(Int64Bytes(ysize))
	buf.Write(ybz)
	buf.Write(Int64Bytes(dsize))
	buf.Write(dbz)
	return buf.Bytes(), nil
}

func (priv *PrivateKey) UnmarshalBinary(data []byte) error {
	xsize, _ := binary.Varint(data)
	xbz := data[8 : 8+int(xsize)]
	data = data[8+int(xsize):]
	ysize, _ := binary.Varint(data)
	ybz := data[8 : 8+int(ysize)]
	data = data[8+int(ysize):]
	dsize, _ := binary.Varint(data)
	dbz := data[8 : 8+int(dsize)]
	data = data[8+int(dsize):]
	if len(data) > 0 {
		return errors.New("Bytes left over")
	}
	priv.key.X.SetBytes(xbz)
	priv.key.Y.SetBytes(ybz)
	priv.key.D.SetBytes(dbz)
	priv.key.Curve = curve
	return nil
}

func (priv *PrivateKey) MarshalJSON() ([]byte, error) {
	data, err := json.Marshal(priv.key)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (priv *PrivateKey) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, priv); err != nil {
		return err
	}
	priv.key.Curve = curve
	return nil
}

func (priv *PrivateKey) Sign(data []byte) *Signature {
	hash := NewHash()
	hash.Write(data)
	h := hash.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, &priv.key, h)
	Check(err)
	sig := NewSignature(r, s)
	return sig
}

// PublicKey

func (pub *PublicKey) MarshalBinary() ([]byte, error) {
	xbz := pub.key.X.Bytes()
	ybz := pub.key.Y.Bytes()
	xsize := int64(binary.Size(xbz))
	ysize := int64(binary.Size(ybz))
	buf := new(bytes.Buffer)
	buf.Write(Int64Bytes(xsize))
	buf.Write(xbz)
	buf.Write(Int64Bytes(ysize))
	buf.Write(ybz)
	return buf.Bytes(), nil
}

func (pub *PublicKey) UnmarshalBinary(data []byte) error {
	xsize, _ := binary.Varint(data)
	xbz := data[8 : 8+int(xsize)]
	data = data[8+int(xsize):]
	ysize, _ := binary.Varint(data)
	ybz := data[8 : 8+int(ysize)]
	data = data[8+int(ysize):]
	if len(data) > 0 {
		return errors.New("Bytes left over")
	}
	pub.key.X.SetBytes(xbz)
	pub.key.Y.SetBytes(ybz)
	pub.key.Curve = curve
	return nil
}

func (pub *PublicKey) MarshalJSON() ([]byte, error) {
	data, err := json.Marshal(pub.key)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (pub *PublicKey) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, pub); err != nil {
		return err
	}
	pub.key.Curve = curve
	return nil
}

func (pub *PublicKey) Verify(data []byte, hash hash.Hash, sig *Signature) bool {
	hash.Reset()
	hash.Write(data)
	h := hash.Sum(nil)
	verified := ecdsa.Verify(&pub.key, h, sig.r, sig.s)
	return verified
}

// Signature

func (sig *Signature) MarshalBinary() ([]byte, error) {
	rbz := sig.r.Bytes()
	sbz := sig.s.Bytes()
	rsize := int64(binary.Size(rbz))
	ssize := int64(binary.Size(sbz))
	buf := new(bytes.Buffer)
	buf.Write(Int64Bytes(rsize))
	buf.Write(rbz)
	buf.Write(Int64Bytes(ssize))
	buf.Write(sbz)
	return buf.Bytes(), nil
}

func (sig *Signature) UnmarshalBinary(data []byte) error {
	rsize, _ := binary.Varint(data)
	rbz := data[8 : 8+int(rsize)]
	data = data[8+int(rsize):]
	ssize, _ := binary.Varint(data)
	sbz := data[8 : 8+int(ssize)]
	data = data[8+int(ssize):]
	if len(data) > 0 {
		return errors.New("Bytes left over")
	}
	sig.r.SetBytes(rbz)
	sig.s.SetBytes(sbz)
	return nil
}

func (sig *Signature) MarshalJSON() ([]byte, error) {
	data, err := json.Marshal(sig)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (sig *Signature) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, sig); err != nil {
		return err
	}
	return nil
}
