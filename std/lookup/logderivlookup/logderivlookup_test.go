package logderivlookup

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

type LookupCircuit struct {
	PubDummy          frontend.Variable `gnark:",public"`
	Entries           [1000]frontend.Variable
	Queries, Expected [100]frontend.Variable
}

func (c *LookupCircuit) Define(api frontend.API) error {
	t := New(api)
	for i := range c.Entries {
		t.Insert(c.Entries[i])
	}
	results := t.Lookup(c.Queries[:]...)
	if len(results) != len(c.Expected) {
		return fmt.Errorf("length mismatch")
	}
	for i := range results {
		api.AssertIsEqual(results[i], c.Expected[i])
	}
	api.AssertIsEqual(c.PubDummy, 0)
	return nil
}

func TestLookup(t *testing.T) {
	assert := test.NewAssert(t)
	field := ecc.BN254.ScalarField()
	witness := LookupCircuit{PubDummy: 0}
	bound := big.NewInt(int64(len(witness.Entries)))
	for i := range witness.Entries {
		witness.Entries[i], _ = rand.Int(rand.Reader, field)
	}
	for i := range witness.Queries {
		q, _ := rand.Int(rand.Reader, bound)
		witness.Queries[i] = q
		witness.Expected[i] = new(big.Int).Set(witness.Entries[q.Int64()].(*big.Int))
	}

	fmt.Println("compile")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &LookupCircuit{PubDummy: 0})
	assert.NoError(err)

	fmt.Println("new witness")
	w, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	fmt.Println("solve")
	_, err = ccs.Solve(w)
	assert.NoError(err)

	fmt.Println("test.IsSolved")
	err = test.IsSolved(&LookupCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	fmt.Println("ProverSucceeded")
	assert.ProverSucceeded(&LookupCircuit{}, &witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16))
}

func TestSolidityExport(t *testing.T) {
	assert := test.NewAssert(t)
	witness := LookupCircuit{PubDummy: 0}
	for i := range witness.Entries {
		witness.Entries[i] = i
	}
	for i := range witness.Queries {
		witness.Queries[i] = i
		witness.Expected[i] = i
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &LookupCircuit{PubDummy: 0})
	assert.NoError(err)

	w, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	assert.NoError(err)
	publicWitness, err := w.Public()
	assert.NoError(err)
	pk, vk, err := groth16.Setup(ccs)
	assert.NoError(err)
	proof, err := groth16.Prove(ccs, pk, w)
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
