package keccaklookup

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func TestSplitMerge(t *testing.T) {
	c := &BenchmarkCircuit{
		Input: Word{
			Val:  parseBinary("1234567812345678123456781234567812345678123456781234567812345678"),
			Size: 64,
		},
		partSize: 8,
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
	check(err)
	fmt.Println("constraints", cs.GetNbConstraints())
}

type BenchmarkCircuit struct {
	Input    Word `gnark:",public"`
	partSize int  `gnark:"-"`
}

func (c *BenchmarkCircuit) Define(api frontend.API) error {
	wa := newWordAPI(api)
	w := c.Input
	for i := 0; i < 100000; i++ {
		split := wa.split(w, c.partSize)
		merged := wa.merge(split)
		api.AssertIsEqual(merged.Val, w.Val)
		w.Val = api.Add(w.Val, 1)
	}
	return nil
}
