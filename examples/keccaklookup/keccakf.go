package keccaklookup

import (
	"fmt"
	"math"
	"time"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

var rotc = [24]int{
	1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
	27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
}

var piln = [24]int{
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
	15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
}

type KeccakfAPI struct {
	api                frontend.API
	wa                 *wordapi
	rc                 [24]Words
	k                  int
	xorTable, chiTable *logderivlookup.Table
}

// NewKeccakfAPI creates KeccakfAPI. k value is word size for the xor and chi tables.
// e.g. if k = 4, then xor table would have 2^(4*2) rows and chi table would have 2^(4*3) rows.
func NewKeccakfAPI(api frontend.API, k int) *KeccakfAPI {
	rc := [24]Words{
		constWords64(0x0000000000000001, k),
		constWords64(0x0000000000008082, k),
		constWords64(0x800000000000808A, k),
		constWords64(0x8000000080008000, k),
		constWords64(0x000000000000808B, k),
		constWords64(0x0000000080000001, k),
		constWords64(0x8000000080008081, k),
		constWords64(0x8000000000008009, k),
		constWords64(0x000000000000008A, k),
		constWords64(0x0000000000000088, k),
		constWords64(0x0000000080008009, k),
		constWords64(0x000000008000000A, k),
		constWords64(0x000000008000808B, k),
		constWords64(0x800000000000008B, k),
		constWords64(0x8000000000008089, k),
		constWords64(0x8000000000008003, k),
		constWords64(0x8000000000008002, k),
		constWords64(0x8000000000000080, k),
		constWords64(0x000000000000800A, k),
		constWords64(0x800000008000000A, k),
		constWords64(0x8000000080008081, k),
		constWords64(0x8000000000008080, k),
		constWords64(0x0000000080000001, k),
		constWords64(0x8000000080008008, k),
	}
	return &KeccakfAPI{
		api:      api,
		wa:       newWordAPI(api),
		k:        k,
		rc:       rc,
		xorTable: newXorTable(api, k),
		chiTable: newChiTable(api, k),
	}
}

func print(i int, st [25]Words) {
	fmt.Printf("%d ", i)
	for _, s := range st {
		fmt.Printf("%s", s)
	}
	fmt.Printf("\n")
}

func (ka *KeccakfAPI) Permute(st [25]Words) [25]Words {
	var bc [5]Words
	var t Words
	for round := 0; round < 24; round++ {
		// theta
		thetaTime := time.Now()
		for i := 0; i < 5; i++ {
			bc[i] = ka.xor(st[i], st[i+5], st[i+10], st[i+15], st[i+20])
		}
		for i := 0; i < 5; i++ {
			rotated := ka.wa.lrot(bc[(i+1)%5], 64-1, ka.k)
			t = ka.xor(bc[(i+4)%5], rotated)
			for j := 0; j < 25; j += 5 {
				st[j+i] = ka.xor(st[j+i], t)
			}
		}
		fmt.Printf("round %d theta took %s\n", round, time.Since(thetaTime))
		// rho pi
		rhopiTime := time.Now()
		t = st[1]
		for i := 0; i < 24; i++ {
			j := piln[i]
			bc[0] = st[j]
			st[j] = ka.wa.lrot(t, 64-rotc[i], ka.k)
			t = bc[0]
		}
		fmt.Printf("round %d rho pi took %s\n", round, time.Since(rhopiTime))
		// chi
		chiTime := time.Now()
		for j := 0; j < 25; j += 5 {
			for i := 0; i < 5; i++ {
				bc[i] = st[j+i]
			}
			for i := 0; i < 5; i++ {
				st[j+i] = ka.chi(bc[(i+1)%5], bc[(i+2)%5], st[j+i])
			}
		}
		fmt.Printf("round %d chi took %s\n", round, time.Since(chiTime))
		// iota
		iotaTime := time.Now()
		st[0] = ka.xor(st[0], ka.rc[round])
		fmt.Printf("round %d iota took %s\n", round, time.Since(iotaTime))
	}
	return st
}

func (k *KeccakfAPI) chi(a, b, c Words) Words {
	if len(a) != len(b) || len(a) != len(c) {
		panic(fmt.Sprintf("chi words len mismatch: a %d, b %d, c %d", a, b, c))
	}
	var ret Words
	for i := range a {
		// Note: for now if the size of the word a, b, and c are not equal to k, the lookup would
		// give wrong result. TODO: check and pad a, b, c to correct size before lookup.
		merged := k.wa.merge(Words{a[i], b[i], c[i]})
		t := time.Now()
		res := k.chiTable.Lookup(merged.Val)
		fmt.Println("chi lookup took", time.Since(t))
		ret = append(ret, Word{Val: res[0], Size: a[i].Size})
	}
	return ret
}

func (k *KeccakfAPI) xor(ins ...Words) Words {
	if len(ins) < 2 {
		panic("xor input length < 2")
	}
	xored := ins[0]
	for i := 1; i < len(ins); i++ {
		xored = k.xor2(xored, ins[i])
	}
	return xored
}

func (k *KeccakfAPI) xor2(a, b Words) Words {
	if len(a) != len(b) {
		panic(fmt.Sprintf("cannot xor2: a len %d, b len %d", len(a), len(b)))
	}
	var ret Words
	for i := range a {
		if a[i].Size != b[i].Size {
			panic(fmt.Sprintf("cannot xor: a[%d].size (%d) != b[%d].size (%d)", i, a[i].Size, i, b[i].Size))
		}
		merged := k.wa.merge(Words{a[i], b[i]})
		t := time.Now()
		xored := k.xorTable.Lookup(merged.Val)
		fmt.Println("xor lookup took", time.Since(t))
		ret = append(ret, Word{Val: xored[0], Size: a[i].Size})
	}
	return ret
}

func newXorTable(api frontend.API, k int) *logderivlookup.Table {
	var vals []frontend.Variable
	count := int(math.Pow(2, float64(k)))
	for i := 0; i < count; i++ {
		for j := 0; j < count; j++ {
			vals = append(vals, i^j)
		}
	}
	table := logderivlookup.New(api)
	for _, val := range vals {
		table.Insert(val)
	}
	fmt.Printf("inserted %d items into xor table\n", len(vals))
	return table
}

func newChiTable(api frontend.API, k int) *logderivlookup.Table {
	var vals []frontend.Variable
	count := int(math.Pow(2, float64(k)))
	for a := 0; a < count; a++ {
		for b := 0; b < count; b++ {
			for c := 0; c < count; c++ {
				vals = append(vals, ((^a)&b)^c)
			}
		}
	}
	table := logderivlookup.New(api)
	for _, val := range vals {
		table.Insert(val)
	}
	fmt.Printf("inserted %d items into chi table\n", len(vals))
	return table
}
