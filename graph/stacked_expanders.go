package graph

import (
	"github.com/pkg/errors"
	. "github.com/zballs/pos/util"
)

type StackedExpanders struct {
	*Graph
}

func (_ *StackedExpanders) IsGraphType() string { return STACKED_EXPANDERS }

func DefaultStackedExpanders(id int) (*Graph, error) {
	return ConstructStackedExpanders(id, 256, 8, 4, false)
}

// Adapted from "Proof of Space from Stacked Expanders", 2016 (Ren, Devadas)

func ConstructStackedExpanders(id int, n, k, d int64, localize bool) (graph *Graph, err error) {
	size := n * (k + 1)
	stacked := new(StackedExpanders)
	stacked.Graph, err = NewGraph(id, size, STACKED_EXPANDERS)
	if err != nil {
		return nil, err
	}
	var nd *Node
	var idx, m int64
	// Create nodes
	for idx < stacked.size {
		nd = NewNode(idx)
		stacked.putBatch(nd)
		if idx++; idx%BATCH_SIZE == 0 || idx == stacked.size {
			if err = stacked.writeBatch(); err != nil {
				return nil, err
			}
		}
	}
	// Stack bipartite expanders
	for ; m <= stacked.size-2*n; m += n {
		if localize {
			if err = stacked.PinskerExpander(m, n, d, true); err != nil {
				return nil, err
			}
		} else {
			if err = stacked.ChungExpander(m, n, d); err != nil {
				return nil, err
			}
		}
	}
	graph = stacked.Graph
	if err = graph.SetType(stacked); err != nil {
		return nil, err
	}
	return graph, nil
}

// This implements Pinsker's randomized construction of a bipartite expander.
// We iterate through the sinks and randomly choose d predecessors for each.
// The localization transformation works as follows... each edge from
// source i to sink j where (i mod n) < (j mod n) is replaced by an edge
// from sink k to sink j where (i mod n) == (k mod n). After the randomized
// construction, any edge from source i to sink j where (i mod n) == (j mod n)
// that does not already exist is added to the graph..
func (stacked *StackedExpanders) PinskerExpander(m, n, d int64, localize bool) error {
	var count, sink, src int64
	for sink = m + n; sink < m+2*n; sink++ {
		count = 0
		nd, err := stacked.Get(sink)
		if err != nil {
			return err
		}
		for count < d {
			src = Rand(n) + m
			if localize {
				if sink = src + n; sink < nd.Idx {
					src = sink
				}
			}
			if nd.AddParent(src) {
				count++
			} else {
				// We already have edge to source
			}
		}
		if localize {
			// Try to add edge to partner
			if src = nd.Idx - n; nd.AddParent(src) {
				// Ok..
			} else {
				// We already have edge to partner
			}
		}
		if sink%BATCH_SIZE == 0 || sink+1 == m+2*n {
			if err := stacked.writeBatch(); err != nil {
				return err
			}
		}
	}
	return nil
}

// This implements Chung's randomized construction of a bipartite expander
// Each source has d outgoing edges and each sink has d incoming edges.
// We establish a one-to-one matching between sources and sinks by
// iterating through the sources and randomly selecting a sink for each.
// If the chosen sink already has a parent, we search outwards until we
// find an available sink. Once we have the random permutation, we add d-1
// more incoming edges to each sink. These edges come from the d-1 sources
// immediately after the matching source (we loop around if we reach m+2*n)
// TODO: add localization transformation..
func (stacked *StackedExpanders) ChungExpander(m, n, d int64) error {
	var iter, sink, src int64
	// Random permutation // 1-1 matching of sources and sinks
	for src = m; src < m+n; src++ {
		sink = Rand(n) + m + n
		nd, err := stacked.Get(sink)
		if err != nil {
			return err
		}
		if nd.NoParents() {
			if !nd.AddParent(src) {
				return errors.New("Failed to add parent")
			}
		} else {
			for iter = 1; ; iter++ {
				if sink+iter >= m+2*n {
					if sink-iter < m+n {
						return errors.New("Could not pair source with sink")
					}
				}
				if sink+iter < m+2*n {
					nd, err = stacked.Get(sink + iter)
					if err != nil {
						return err
					}
					if nd.NoParents() {
						if !nd.AddParent(src) {
							return errors.New("Failed to add parent")
						}
						break
					}
				}
				if sink-iter >= m+n {
					nd, err = stacked.Get(sink - iter)
					if err != nil {
						return err
					}
					if nd.NoParents() {
						if !nd.AddParent(src) {
							return errors.New("Failed to add parent")
						}
						break
					}
				}
			}
		}
		if err := stacked.put(nd); err != nil {
			return err
		}
	}
	for sink = m + n; sink < m+2*n; sink++ {
		nd, err := stacked.Get(sink)
		if err != nil {
			return err
		}
		if numParents := nd.Parents.Len(); numParents != 1 {
			return errors.Errorf("Expected 1 parent; got %d parents", numParents)
		}
		for iter, src = 1, nd.Parents[0]; iter < d; iter++ {
			if src+iter == m+n {
				src = m - iter
			}
			if !nd.AddParent(src + iter) {
				return errors.New("Failed to add parent")
			}
		}
		stacked.putBatch(nd)
		if sink%BATCH_SIZE == 0 || sink+1 == m+2*n {
			if err := stacked.writeBatch(); err != nil {
				return err
			}
		}
	}
	return nil
}
