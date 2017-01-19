package crypto

import (
	"testing"
)

func TestCrypto(t *testing.T) {
	msg := []byte("deadbeef")
	// Generate keypair
	priv, pub := GenerateKeypair()
	// Sign message
	sig, err := priv.Sign(msg)
	if err != nil {
		t.Error(err.Error())
	}
	// Verify that sig is valid signature of msg
	if !pub.Verify(msg, sig) {
		t.Error("Signature verification failed")
	}
}
