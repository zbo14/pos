package graph

import . "github.com/zballs/pos/util"

// Linear SuperConcentrator

type LinearSuperConcentrator struct {
	*Graph
}

func (_ *LinearSuperConcentrator) IsGraphType() string { return LINEAR_SUPER_CONCENTRATOR }

func DefaultLinearSuperConcentrator(id int) *Graph {
	return ConstructLinearSuperConcentrator(id, 256, 3, 4, true)
}

// Builds a linear superconcentrator with n inputs and n outputs

func ConstructLinearSuperConcentrator(id int, n, k, d int64, localize bool) *Graph {
	var i, m, _n int64
	if !PowOf2(n) {
		panic("n must be a power of 2")
	}
	if Log2(n)/2 < k {
		panic("n must be a higher power of 2")
	}
	for m, _n = 0, n; i < k; i++ {
		m += _n
		_n *= (3 / 4)
	}
	m = m*2 + _n
	sup := new(LinearSuperConcentrator)
	sup.Graph = NewGraph(id, m, LINEAR_SUPER_CONCENTRATOR)
	Println(sup.size)
	var idx, j int64
	var nd *Node
	for ; idx < sup.size; idx++ {
		nd = NewNode(idx)
		sup.putBatch(nd)
		if (idx+1)%BATCH_SIZE == 0 || (idx+1) == sup.size {
			sup.writeBatch()
		}
	}
	for i, m, _n = 0, 0, n; i < k; i++ {
		// Concentrator
		sup.Concentrator(m, _n, d, localize, false)
		// Reverse concentrator
		_m := sup.size - (m + 7*_n/4)
		sup.Concentrator(_m, _n, d, localize, true)
		// Perfect matching
		for j = 0; j < _n; j++ {
			nd = NewNode(idx)
			if !nd.AddParent(sup.size + j - m - _n) {
				panic("Failed to add parent")
			}
			sup.putBatch(nd)
			if idx++; idx%BATCH_SIZE == 0 || idx == sup.size {
				sup.writeBatch()
			}
		}
		m += _n
		_n *= (3 / 4)
	}
	// Finish perfect matching in middle section
	for idx = m; idx < m+_n/2; {
		nd := sup.Get(idx)
		if !nd.AddParent(m*2 + _n - idx) {
			panic("Failed to add parent")
		}
		sup.putBatch(nd)
		if idx++; idx%BATCH_SIZE == 0 || idx == m+_n/2 {
			sup.writeBatch()
		}
	}
	graph := sup.Graph
	if !graph.SetType(sup) {
		panic("Graph type already set")
	}
	return graph
}

// A left expander output will have d incoming edges from inputs
// and one incoming edge from a leftover node in the concentrator.
// A right expander output will have d incoming edges from inputs
// and one incoming edge from the perfect matching..
func (sup *LinearSuperConcentrator) Concentrator(m, n, d int64, localize, reverse bool) {
	_m, _n := m, 3*n/4
	if !reverse {
		_m += (n - _n)
	}
	// Expander
	sup.PinskerExpander(_m, _n, d, localize)
	// Leftover edges
	var nd *Node
	if !reverse {
		for src := m; src < _m; {
			for sink := m + n + (src-m)*3; sink < m+n+(src-m+1)*3; sink++ {
				nd = sup.Get(sink)
				if !nd.AddParent(src) {
					panic("Failed to add parent")
				}
				sup.putBatch(nd)
			}
			if src++; src%BATCH_SIZE == 0 || src == _m {
				sup.writeBatch()
			}
		}
	} else {
		for sink := m + 2*_n; sink < m+n+_n; {
			nd := sup.Get(sink)
			for src := m + (sink-m-2*_n)*3; src < m+(sink-m-2*_n+1)*3; src++ {
				if !nd.AddParent(src) {
					panic("Failed to add parent")
				}
				sup.putBatch(nd)
			}
			if sink++; sink%BATCH_SIZE == 0 || sink == m+n-_n {
				sup.writeBatch()
			}
		}
	}
}

// Bipartite Expander
func (sup *LinearSuperConcentrator) PinskerExpander(m, n, d int64, localize bool) {
	var count, sink, src int64
	for sink = m + n; sink < m+2*n; sink++ {
		count = 0
		nd := sup.Get(sink)
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
			sup.writeBatch()
		}
	}
}
