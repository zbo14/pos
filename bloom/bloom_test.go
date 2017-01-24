package bloom

import (
	"testing"
)

var items = [][]byte{
	[]byte("abc"),
	[]byte("xyz"),
	[]byte("hello world"),
	[]byte("deadbeef"),
	[]byte("foobar"),
	[]byte("foobaz"),
	[]byte("testing testing.."),
	[]byte("merkle derp"),
	[]byte("number 9"),
}

var other_items = [][]byte{
	[]byte("can you find me?"),
	[]byte("i am not in the bloom filter"),
	[]byte("i am also not in the bloom filter"),
}

func TestBloom(t *testing.T) {
	capacity := len(items)
	filter := NewFilter(capacity)
	for _, item := range items {
		if !filter.Add(item) {
			t.Error("Failed to add item to bloom filter")
		}
	}
	for _, item := range items {
		if !filter.Has(item) {
			t.Error("Failed to find item in bloom filter")
		}
	}
	for _, other := range other_items {
		if filter.Has(other) {
			t.Errorf("Bloom filter does not have item=%s\n", other)
		}
	}
}
