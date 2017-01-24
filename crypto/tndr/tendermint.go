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
