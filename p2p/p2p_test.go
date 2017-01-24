package p2p

import (
	"testing"
)

func TestTypes(t *testing.T) {
	data := []byte("here is some data that will be in a part set")
	partSet, err := NewPartSetFromData(data, 1)
	if err != nil {
		t.Fatal(err.Error())
	}
	reader := partSet.GetReader()
	p := make([]byte, 4)
	_, err = reader.Read(p)
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Log(string(p))
}
