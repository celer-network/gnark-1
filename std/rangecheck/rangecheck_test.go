package rangecheck

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

type CheckCircuit struct {
	PubDummy frontend.Variable `gnark:",public"`
	Vals     []frontend.Variable
	bits     int
}

func (c *CheckCircuit) Define(api frontend.API) error {
	r := newCommitRangechecker(api)
	for i := range c.Vals {
		r.Check(c.Vals[i], c.bits)
	}
	return nil
}

func TestCheck(t *testing.T) {
	assert := test.NewAssert(t)
	var err error
	bits := 64
	nbVals := 100000
	bound := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	vals := make([]frontend.Variable, nbVals)
	for i := range vals {
		vals[i], err = rand.Int(rand.Reader, bound)
		if err != nil {
			t.Fatal(err)
		}
	}
	witness := CheckCircuit{Vals: vals, bits: bits}
	circuit := CheckCircuit{Vals: make([]frontend.Variable, len(vals)), bits: bits}
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
	_, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit, frontend.WithCompressThreshold(100))
	assert.NoError(err)
}

func TestSolidityExport(t *testing.T) {
	assert := test.NewAssert(t)
	var err error
	bits := 64
	nbVals := 100
	bound := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	vals := make([]frontend.Variable, nbVals)
	for i := range vals {
		vals[i], err = rand.Int(rand.Reader, bound)
		if err != nil {
			t.Fatal(err)
		}
	}
	witness := CheckCircuit{PubDummy: 0, Vals: vals, bits: bits}
	circuit := CheckCircuit{PubDummy: 0, Vals: make([]frontend.Variable, len(vals)), bits: bits}
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit, frontend.WithCompressThreshold(100))
	assert.NoError(err)
	w, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	assert.NoError(err)
	publicWitness, err := w.Public()
	assert.NoError(err)
	pk, vk, err := groth16.Setup(cs)
	assert.NoError(err)
	proof, err := groth16.Prove(cs, pk, w)
	assert.NoError(err)

	a, b, c, commitments, commitmentPok := ExportProof(proof)
	fmt.Println("a:", a, "b:", b, "c:", c, "commit:", commitments, "pok:", commitmentPok)
	wvec, ok := publicWitness.Vector().(fr_bn254.Vector)
	if !ok {
		panic("publicWitness.Vector")
	}
	fmt.Println("wvec", wvec)

	err = groth16.Verify(proof, vk, publicWitness)
	assert.NoError(err)

	fmt.Println("groth16 verify finished")

	f, err := os.Create("LookUpTest.sol")
	if err != nil {
		assert.NoError(err)
	}

	defer f.Close()
	err = vk.ExportSolidity(f)
	assert.NoError(err)
	panic("")
}

func ExportProof(proof groth16.Proof) (a [2]*big.Int, b [2][2]*big.Int, c [2]*big.Int, commitment [2]*big.Int, commitmentPok [2]*big.Int) {
	var buf bytes.Buffer
	const fpSize = 4 * 8
	_, err := proof.WriteRawTo(&buf)
	if err != nil {
		fmt.Print(err)
	}
	proofBytes := buf.Bytes()

	a[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	a[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	b[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	b[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	b[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	b[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	c[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	c[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])
	commitment[0] = new(big.Int).SetBytes(proofBytes[fpSize*8 : fpSize*9])
	commitment[1] = new(big.Int).SetBytes(proofBytes[fpSize*9 : fpSize*10])
	commitmentPok[0] = new(big.Int).SetBytes(proofBytes[fpSize*10 : fpSize*11])
	commitmentPok[1] = new(big.Int).SetBytes(proofBytes[fpSize*11 : fpSize*12])
	return
}
