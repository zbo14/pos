package tndr

import (
	"github.com/tendermint/go-crypto"
	. "github.com/zballs/pos/util"
	bcrypt "golang.org/x/crypto/bcrypt"
)

func PubKey(priv crypto.PrivKeyEd25519) crypto.PubKeyEd25519 {
	return priv.PubKey().(crypto.PubKeyEd25519)
}

func Sign(priv crypto.PrivKeyEd25519, msg []byte) crypto.SignatureEd25519 {
	return priv.Sign(msg).(crypto.SignatureEd25519)
}

func GeneratePrivKey(password string) crypto.PrivKeyEd25519 {
	secret, err := bcrypt.GenerateFromPassword([]byte(password), 0)
	Check(err)
	priv := crypto.GenPrivKeyEd25519FromSecret(secret)
	return priv
}

func PrivKeyToHex(priv crypto.PrivKeyEd25519) string {
	return EncodeHex(priv[:])
}

func PrivKeyFromHex(hex string) (priv crypto.PrivKeyEd25519) {
	bytes := MustDecodeHex(hex)
	copy(priv[:], bytes)
	return
}

func PrivKeyToB58(priv crypto.PrivKeyEd25519) string {
	return EncodeB58(priv[:])
}

func PrivKeyFromB58(b58 string) (priv crypto.PrivKeyEd25519) {
	bytes := DecodeB58(b58)
	copy(priv[:], bytes)
	return
}
