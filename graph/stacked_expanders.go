package graph

import . "github.com/zballs/pos/util"

type StackedExpanders struct {
	*Graph
}

func (_ *StackedExpanders) IsGraphType() string { return STACKED_EXPANDERS }

func DefaultStackedExpanders(id int) *Graph {
	return ConstructStackedExpanders(id, 2048, 31, 5, false) //size = 65536
}

// Adapted from "Proof of Space from Stacked Expanders", 2016 (Ren, Devadas)

func ConstructStackedExpanders(id int, n, k, d int64, localize bool) *Graph {
	size := n * (k + 1)
	stacked := new(StackedExpanders)
	stacked.Graph = NewGraph(id, size, STACKED_EXPANDERS)
	var nd *Node
	var idx, m int64
	// Create nodes
	for idx < stacked.size {
		nd = NewNode(idx)
		stacked.putBatch(nd)
		if idx++; idx%BATCH_SIZE == 0 || idx == stacked.size {
			stacked.writeBatch()
		}
	}
	// Stack bipartite expanders
	for ; m <= stacked.size-2*n; m += n {
		if localize {
			stacked.PinskerExpander(m, n, d, true)
		} else {
			stacked.ChungExpander(m, n, d)
		}
	}
	graph := stacked.Graph
	if !graph.SetType(stacked) {
		panic("Graph type already set")
	}
	return graph
}

// This implements Pinsker's randomized construction of a bipartite expander.
// We iterate through the sinks and randomly choose d predecessors for each.
// The localization transformation works as follows... each edge from
// source i to sink j where (i mod n) < (j mod n) is replaced by an edge
// from sink k to sink j where (i mod n) == (k mod n). After the randomized
// construction, any edge from source i to sink j where (i mod n) == (j mod n)
// that does not already exist is added to the graph..
func (stacked *StackedExpanders) PinskerExpander(m, n, d int64, localize bool) {
	var count, sink, src int64
	for sink = m + n; sink < m+2*n; sink++ {
		count = 0
		nd := stacked.Get(sink)
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
			stacked.writeBatch()
		}
	}
}

// This implements Chung's randomized construction of a bipartite expander
// Each source has d outgoing edges and each sink has d incoming edges.
// We establish a one-to-one matching between sources and sinks by
// iterating through the sources and randomly selecting a sink for each.
// If the chosen sink already has a parent, we search outwards until we
// find an available sink. Once we have the random permutation, we add d-1
// more incoming edges to each sink. These edges come from the d-1 sources
// immediately after the matching source (we loop around if we reach m+2*n)
// TODO: add localization transformation
// TODO: more explicit panic messages
func (stacked *StackedExpanders) ChungExpander(m, n, d int64) {
	var iter, sink, src int64
	// Random permutation // 1-1 matching of sources and sinks
	for src = m; src < m+n; src++ {
		sink = Rand(n) + m + n
		nd := stacked.Get(sink)
		if nd.NoParents() {
			if !nd.AddParent(src) {
				panic("Failed to add parent")
			}
		} else {
			for iter = 1; ; iter++ {
				if sink+iter >= m+2*n {
					if sink-iter < m+n {
						panic("Could not pair source with sink")
					}
				}
				if sink+iter < m+2*n {
					nd = stacked.Get(sink + iter)
					if nd.NoParents() {
						if !nd.AddParent(src) {
							panic("Failed to add parent")
						}
						break
					}
				}
				if sink-iter >= m+n {
					nd = stacked.Get(sink - iter)
					if nd.NoParents() {
						if !nd.AddParent(src) {
							panic("Failed to add parent")
						}
						break
					}
				}
			}
		}
		stacked.put(nd)
	}
	for sink = m + n; sink < m+2*n; sink++ {
		nd := stacked.Get(sink)
		if numParents := nd.Parents.Len(); numParents != 1 {
			Panicf("Expected 1 parent; got %d parents", numParents)
		}
		for iter, src = 1, nd.Parents[0]; iter < d; iter++ {
			if src+iter == m+n {
				src = m - iter
			}
			if !nd.AddParent(src + iter) {
				panic("Failed to add parent")
			}
		}
		stacked.putBatch(nd)
		if sink%BATCH_SIZE == 0 || sink+1 == m+2*n {
			stacked.writeBatch()
		}
	}
}
