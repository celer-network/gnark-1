package keccaklookup

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

func TestWordAPI(t *testing.T) {
	c := &TestCircuit{
		Words: Words{
			parseBinary("10001001"),
			parseBinary("01010100"),
			parseBinary("11001101"),
		},
	}
	w := &TestCircuit{
		Words: Words{
			parseBinary("10001001"),
			parseBinary("01010100"),
			parseBinary("11001101"),
		},
	}
	err := test.IsSolved(c, w, ecc.BN254.ScalarField())
	check(err)

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
	check(err)
	fmt.Println("constraints", cs.GetNbConstraints())
}

type TestCircuit struct {
	Words Words
}

func (c *TestCircuit) Define(api frontend.API) error {
	wa := newWordAPI(api)
	w := c.Words[0]
	split := wa.split(w, 8)
	checkLen(split, 1)
	api.AssertIsEqual(split.totalSize(), w.Size)
	api.AssertIsEqual(split[0].Val, parseBinary("10001001").Val)

	split = wa.split(w, 4)
	checkLen(split, 2)
	api.AssertIsEqual(split.totalSize(), w.Size)
	api.AssertIsEqual(split[0].Val, parseBinary("1000").Val)
	api.AssertIsEqual(split[0].Size, 4)
	api.AssertIsEqual(split[1].Val, parseBinary("1001").Val)
	api.AssertIsEqual(split[1].Size, 4)

	split = wa.split(w, 2, 2)
	checkLen(split, 3)
	api.AssertIsEqual(split.totalSize(), w.Size)
	api.AssertIsEqual(split[0].Val, parseBinary("10").Val)
	api.AssertIsEqual(split[0].Size, 2)
	api.AssertIsEqual(split[1].Val, parseBinary("00").Val)
	api.AssertIsEqual(split[1].Size, 2)
	api.AssertIsEqual(split[2].Val, parseBinary("1001").Val)
	api.AssertIsEqual(split[2].Size, 4)

	rotated := wa.lrotMerge(c.Words, 1)
	api.AssertIsEqual(rotated.Size, 24)
	api.AssertIsEqual(rotated.Val, parseBinary("000100101010100110011011").Val)

	rs := wa.lrot(c.Words, 1, 8)
	checkLen(rs, 3)
	api.AssertIsEqual(rs.totalSize(), 24)
	api.AssertIsEqual(rs[0].Val, parseBinary("00010010").Val)
	api.AssertIsEqual(rs[0].Size, 8)
	api.AssertIsEqual(rs[1].Val, parseBinary("10101001").Val)
	api.AssertIsEqual(rs[1].Size, 8)
	api.AssertIsEqual(rs[2].Val, parseBinary("10011011").Val)
	api.AssertIsEqual(rs[2].Size, 8)

	m := wa.merge(c.Words)
	api.AssertIsEqual(m.Size, 24)
	api.AssertIsEqual(m.Val, parseBinary("100010010101010011001101").Val)
	return nil
}
