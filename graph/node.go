package graph

import (
	"encoding/binary"
	"fmt"
	"github.com/pkg/errors"
	. "github.com/zballs/pos/util"
)

type Node struct {
	Idx     int64
	Parents Int64s
	Value   []byte
}

func NewNode(idx int64) *Node {
	return &Node{
		Idx: idx,
	}
}

func (nd *Node) MarshalBinary() ([]byte, error) {
	data := make([]byte, 8*(len(nd.Parents)+3)+len(nd.Value))
	copy(data[:8], Int64Bytes(nd.Idx))
	numParents := int64(len(nd.Parents))
	n := 16
	copy(data[8:n], Int64Bytes(numParents))
	for _, p := range nd.Parents {
		copy(data[n:n+8], Int64Bytes(p))
		n += 8
	}
	lenValue := len(nd.Value)
	copy(data[n:n+8], Int64Bytes(int64(lenValue)))
	n += 8
	copy(data[n:n+lenValue], nd.Value)
	return data, nil
}

func (nd *Node) UnmarshalBinary(data []byte) error {
	// Note: data should not be modified
	var n int
	nd.Idx, _ = binary.Varint(data)
	n += 8
	numParents, _ := binary.Varint(data[n:])
	n += 8
	nd.Parents = make(Int64s, int(numParents))
	for i, _ := range nd.Parents {
		nd.Parents[i], _ = binary.Varint(data[n:])
		n += 8
	}
	lenValue, _ := binary.Varint(data[n:])
	n += 8
	nd.Value = data[n : n+int(lenValue)]
	if len(data) != n+int(lenValue) {
		return errors.New("Bytes left over")
	}
	return nil
}

func (nd *Node) AddParent(parent int64) bool {
	if nd.Idx == parent {
		// same node
		panic("Node cannot be its own parent")
	}
	for _, p := range nd.Parents {
		if p == parent {
			// nd already has parent
			return false
		}
	}
	nd.Parents = append(nd.Parents, parent)
	return true
}

func (nd *Node) NoParents() bool {
	return len(nd.Parents) == 0
}

func (nd *Node) String() string {
	return fmt.Sprintf("NODE(idx=%d,parents=%v,value=%x)\n", nd.Idx, nd.Parents, nd.Value)
}

type Nodelist []*Node

// Sort nodelist by node idxs

func (lst Nodelist) Len() int {
	return len(lst)
}

func (lst Nodelist) Less(i, j int) bool {
	return lst[i].Idx < lst[j].Idx
}

func (lst Nodelist) Size() int64 {
	return int64(len(lst))
}

func (lst Nodelist) Swap(i, j int) {
	lst[i], lst[j] = lst[j], lst[i]
}
