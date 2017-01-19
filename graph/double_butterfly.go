package graph

import (
	"github.com/pkg/errors"
	. "github.com/zballs/pos/util"
)

type DoubleButterfly struct {
	*Graph
}

func (_ *DoubleButterfly) IsGraphType() string { return DOUBLE_BUTTERFLY }

func DefaultDoubleButterfly(id int) (*Graph, error) {
	return ConstructDoubleButterfly(id, 3, 4)
}

// Double Butterfly graph
func ConstructDoubleButterfly(id int, g, l int64) (graph *Graph, err error) {
	if g < 1 {
		return nil, errors.New("g cannot be less than 1")
	}
	vertsPerRow := Pow2(g)
	rowsPerSection := 2 * g
	sectionSize := vertsPerRow * rowsPerSection
	size := vertsPerRow * (l*(rowsPerSection-1) + 1)
	bfly := new(DoubleButterfly)
	bfly.Graph, err = NewGraph(id, size, DOUBLE_BUTTERFLY)
	if err != nil {
		return nil, err
	}
	var i, j, k int64
	var add bool
	var nd *Node
	for ; i < bfly.size; i++ {
		nd = NewNode(i)
		bfly.putBatch(nd)
		if (i+1)%BATCH_SIZE == 0 || i+1 == bfly.size {
			if err := bfly.writeBatch(); err != nil {
				return nil, err
			}
		}
	}
	for i, j = 1, vertsPerRow; i < bfly.size; i++ {
		nd, err := bfly.Get(i)
		if err != nil {
			return nil, err
		}
		// Add sequential edge
		nd.AddParent(i - 1)
		if i >= vertsPerRow {
			// Add vertical edge
			nd.AddParent(i - vertsPerRow)
			// New section?
			if (i+k)%sectionSize == 0 {
				j = vertsPerRow
				k += vertsPerRow
			}
			// What kind of diagonal edge?
			if i%vertsPerRow == 0 {
				if (i+k)%sectionSize/vertsPerRow > g {
					j <<= 1
				} else {
					j >>= 1
				}
				add = true
			} else if i%j == 0 {
				add = !add
			}
			// Add diagonal edge
			if add {
				nd.AddParent(i - vertsPerRow + j)
			} else {
				nd.AddParent(i - vertsPerRow - j)
			}
		}
		bfly.putBatch(nd)
		if i%BATCH_SIZE == 0 || i+1 == bfly.size {
			if err := bfly.writeBatch(); err != nil {
				return nil, err
			}
		}
	}
	graph = bfly.Graph
	if err = graph.SetType(bfly); err != nil {
		return nil, err
	}
	return graph, nil
}
