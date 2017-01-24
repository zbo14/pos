package graph

import (
	"github.com/pkg/errors"
	. "github.com/zballs/pos/util"
)

// Linear SuperConcentrator

type LinearSuperConcentrator struct {
	*Graph
}

func (_ *LinearSuperConcentrator) IsGraphType() string { return LINEAR_SUPER_CONCENTRATOR }

func DefaultLinearSuperConcentrator(id int) (*Graph, error) {
	return ConstructLinearSuperConcentrator(id, 256, 3, 4, true)
}

// Builds a linear superconcentrator with n inputs and n outputs

func ConstructLinearSuperConcentrator(id int, n, k, d int64, localize bool) (graph *Graph, err error) {
	var i, m, _n int64
	if !PowOf2(n) {
		return nil, errors.New("n must be power of 2")
	}
	if Log2(n)/2 < k {
		return nil, errors.New("n must be a higher power of 2")
	}
	for m, _n = 0, n; i < k; i++ {
		m += _n
		_n *= (3 / 4)
	}
	m = m*2 + _n
	sup := new(LinearSuperConcentrator)
	sup.Graph, err = NewGraph(id, m, LINEAR_SUPER_CONCENTRATOR)
	if err != nil {
		return nil, err
	}
	Println(sup.size)
	var idx, j int64
	var nd *Node
	for ; idx < sup.size; idx++ {
		nd = NewNode(idx)
		sup.putBatch(nd)
		if (idx+1)%BATCH_SIZE == 0 || (idx+1) == sup.size {
			if err = sup.writeBatch(); err != nil {
				return nil, err
			}
		}
	}
	for i, m, _n = 0, 0, n; i < k; i++ {
		// Concentrator
		if err = sup.Concentrator(m, _n, d, localize, false); err != nil {
			return nil, err
		}
		// Reverse concentrator
		_m := sup.size - (m + 7*_n/4)
		if err = sup.Concentrator(_m, _n, d, localize, true); err != nil {
			return nil, err
		}
		// Perfect matching
		for j = 0; j < _n; j++ {
			nd = NewNode(idx)
			if !nd.AddParent(sup.size + j - m - _n) {
				panic("Failed to add parent")
			}
			sup.putBatch(nd)
			if idx++; idx%BATCH_SIZE == 0 || idx == sup.size {
				if err = sup.writeBatch(); err != nil {
					return nil, err
				}
			}
		}
		m += _n
		_n *= (3 / 4)
	}
	// Finish perfect matching in middle section
	for idx = m; idx < m+_n/2; {
		nd, err := sup.Get(idx)
		if err != nil {
			return nil, err
		}
		if !nd.AddParent(m*2 + _n - idx) {
			panic("Failed to add parent")
		}
		sup.putBatch(nd)
		if idx++; idx%BATCH_SIZE == 0 || idx == m+_n/2 {
			if err = sup.writeBatch(); err != nil {
				return nil, err
			}
		}
	}
	graph = sup.Graph
	if err = graph.SetType(sup); err != nil {
		return nil, err
	}
	return graph, nil
}

// A left expander output will have d incoming edges from inputs
// and one incoming edge from a leftover node in the concentrator.
// A right expander output will have d incoming edges from inputs
// and one incoming edge from the perfect matching..
func (sup *LinearSuperConcentrator) Concentrator(m, n, d int64, localize, reverse bool) (err error) {
	_m, _n := m, 3*n/4
	if !reverse {
		_m += (n - _n)
	}
	// Expander
	if err = sup.PinskerExpander(_m, _n, d, localize); err != nil {
		return err
	}
	// Leftover edges
	var nd *Node
	if !reverse {
		for src := m; src < _m; {
			for sink := m + n + (src-m)*3; sink < m+n+(src-m+1)*3; sink++ {
				nd, err = sup.Get(sink)
				if err != nil {
					return err
				}
				if !nd.AddParent(src) {
					panic("Failed to add parent")
				}
				sup.putBatch(nd)
			}
			if src++; src%BATCH_SIZE == 0 || src == _m {
				if err = sup.writeBatch(); err != nil {
					return err
				}
			}
		}
	} else {
		for sink := m + 2*_n; sink < m+n+_n; {
			nd, err := sup.Get(sink)
			if err != nil {
				return err
			}
			for src := m + (sink-m-2*_n)*3; src < m+(sink-m-2*_n+1)*3; src++ {
				if !nd.AddParent(src) {
					panic("Failed to add parent")
				}
				sup.putBatch(nd)
			}
			if sink++; sink%BATCH_SIZE == 0 || sink == m+n-_n {
				if err = sup.writeBatch(); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Bipartite Expander
func (sup *LinearSuperConcentrator) PinskerExpander(m, n, d int64, localize bool) error {
	var count, sink, src int64
	for sink = m + n; sink < m+2*n; sink++ {
		count = 0
		nd, err := sup.Get(sink)
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
			if err := sup.writeBatch(); err != nil {
				return err
			}
		}
	}
	return nil
}
