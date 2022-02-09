package dag

import (
	"sort"
)

type DAG struct {
	parents  [][]int
	children [][]int
	visited  []int
	nbNodes  int
}

func New(nbNodes int) DAG {
	dag := DAG{
		parents:  make([][]int, nbNodes),
		children: make([][]int, nbNodes),
		visited:  make([]int, nbNodes),
	}

	return dag
}

// AddNode adds a node to the dag
// TODO @gbotrel right now, node is just an ID, but we probably want an interface if perf allows
func (dag *DAG) AddNode() (n int) {
	n = dag.nbNodes
	dag.nbNodes++
	return
}

// AddEdges from parents to n
// parents is mutated and filtered to remove transitive dependencies
func (dag *DAG) AddEdges(n int, parents []int) {
	// sort parents in descending order
	// the rational behind this is (n,m) are nodes, and n > m, it means n
	// was created after m. Hence, it is impossible in our DAGs (we don't modify previous nodes)
	// that n is a parent of m.
	sort.Sort(sort.Reverse(sort.IntSlice(parents)))

	// log.Println("parents before", dbgs(parents))
	for i := 0; i < len(parents); i++ {
		parents = append(parents[:i+1], dag.removeTransitivity(parents[i], parents[i+1:])...)
	}
	// log.Println("parents after", dbgs(parents))

	dag.parents[n] = make([]int, len(parents))

	// set parents of n
	copy(dag.parents[n], parents)

	// for each parent, add a new children: n
	for _, p := range parents {
		dag.children[p] = append(dag.children[p], n)
	}

}

// Levels returns a list of level. For each level l, it is guaranteed that all dependencies
// of the nodes in l are in previous levels
func (dag *DAG) Levels() [][]int {
	// tag the nodes per levels
	capacity := len(dag.children)
	current := make([]int, 0, capacity/2)
	next := make([]int, 0, capacity/2)
	solved := make([]bool, capacity)

	var levels [][]int

	// find the entry nodes: the ones without parents
	for n, p := range dag.parents {
		if len(p) == 0 {
			next = append(next, n)
			solved[n] = true // mark this node as solved
			// push the childs to current
			current = append(current, dag.children[n]...)
		}
	}
	levels = append(levels, make([]int, len(next)))
	copy(levels[0], next)
	sort.Ints(levels[0])

	level := 0

	// we use visited to tag nodes visited per level
	// we set visited[n] = l if we visited n at level l
	// we don't clear the memory between levels.
	for i := 0; i < len(dag.visited); i++ {
		dag.visited[i] = 0
	}

	for {
		next = next[:0]
		if len(current) == 0 {
			break // we're done
		}

		level++
		levels = append(levels, make([]int, 0, len(current)))
		for i := 0; i < len(current); i++ {
			n := current[i]

			// check if we visited this node.
			if dag.visited[n] == level {
				continue
			}
			dag.visited[n] = level

			// if all dependencies of n are solved, we add it to current level.
			unsolved := false
			for _, j := range dag.parents[n] {
				if !solved[j] {
					unsolved = true
					break
				}
			}
			if unsolved {
				// add it to next
				next = append(next, n)
				continue
			}

			// all dependencies are solved, we add it to this level and push its chidren to the next
			levels[level] = append(levels[level], n)
			next = append(next, dag.children[n]...)

		}
		// mark level as solved
		sort.Ints(levels[level])
		for _, n := range levels[level] {
			solved[n] = true
		}
		current, next = next, current
	}
	return levels
}

func (dag *DAG) removeTransitivity(n int, set []int) []int {
	// n > (s in set) ; n is the most recent node, so the one that can't be others ancestors
	// n is not in set

	if len(dag.parents[n]) == 0 {
		// n has no parents, it's an entry node
		return set
	}

	// for each parent p of n, if it is present in the set, we remove it from the set, recursively
	for j := len(dag.parents[n]) - 1; j >= 0; j-- {

		// we filtered them all.
		if len(set) == 0 {
			return nil
		}

		p := dag.parents[n][j]

		// we tag the visited array with the nbNodes value, which is unique to this AddEdges call
		// this enable us to re-use visited []int without mem clear between searches
		if dag.visited[p] == dag.nbNodes {
			continue
		}
		dag.visited[p] = dag.nbNodes

		// log.Printf("processing p:%s parent of %s\n", dbg(p), dbg(n))

		// parents are in descending order; if min value of the set (ie the oldest node) is at
		// the last position. If p (parent of n) is smaller than minSet, it means p is older than
		// all set elements. p's parents will be even olders, and have no chance to appear in the set
		minSet := set[len(set)-1]
		if p < minSet {
			// log.Printf("%s > %s\n", dbg(p), dbg(minSet))
			return set
		}

		// we look for p in the set
		i := sort.Search(len(set), func(i int) bool { return set[i] <= p })
		if i != len(set) && set[i] == p {
			// it is in the set, remove it
			set = append(set[:i], set[i+1:]...)
			continue
		}

		// it is not in the set, we check its parents
		set = dag.removeTransitivity(p, set)
	}

	return set
}

// test purposes

// func dbgs(v []int) string {
// 	var sbb strings.Builder
// 	sbb.WriteString("[")
// 	for i := 0; i < len(v); i++ {
// 		sbb.WriteString(dbg(v[i]))
// 		if i != len(v)-1 {
// 			sbb.WriteString(", ")
// 		}
// 	}
// 	sbb.WriteString("]")
// 	return sbb.String()
// }

// func dbg(v int) string {
// 	switch v {
// 	case 0:
// 		return "A"
// 	case 1:
// 		return "B"
// 	case 2:
// 		return "C"
// 	case 3:
// 		return "D"
// 	case 4:
// 		return "E"
// 	default:
// 		return strconv.Itoa(v)
// 	}
// }