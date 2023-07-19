package logderivlookup

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/utils"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

type LookupCircuit struct {
	Entries  [10]frontend.Variable
	Queries  [10]frontend.Variable `gnark:",public"`
	Expected [10]frontend.Variable
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
	return nil
}

func TestLookup(t *testing.T) {
	assert := test.NewAssert(t)
	field := ecc.BN254.ScalarField()
	witness := LookupCircuit{}
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
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &LookupCircuit{})
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
	witness := LookupCircuit{}
	for i := range witness.Entries {
		witness.Entries[i] = i
	}
	for i := range witness.Queries {
		witness.Queries[i] = i
		witness.Expected[i] = i
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &LookupCircuit{})
	assert.NoError(err)

	// get public witness
	w, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	assert.NoError(err)
	_publicWitness, err := w.Public()
	assert.NoError(err)
	publicWitness := _publicWitness.Vector().(fr.Vector)
	fmt.Println("publicWitness", publicWitness)

	// setup, get vk pk
	pk, _vk, err := groth16.Setup(ccs)
	assert.NoError(err)
	vk := _vk.(*groth16_bn254.VerifyingKey)
	fmt.Printf("vk.G1.Alpha %s\n", &vk.G1.Alpha)
	for i, k := range vk.G1.K {
		kk := k
		kp := &kk
		fmt.Printf("vk.G1.K[%d] %s\n", i, kp)
	}
	fmt.Println("len vk.PublicAndCommitmentCommitted:", len(vk.PublicAndCommitmentCommitted))
	for _, vi := range vk.PublicAndCommitmentCommitted {
		fmt.Println(vi)
	}

	_proof, err := groth16.Prove(ccs, pk, w)
	assert.NoError(err)
	proof := _proof.(*groth16_bn254.Proof)

	// export proof
	a, b, c, commitments, commitmentPok := ExportProof(proof)
	fmt.Printf(`
const p = {
    a: [
      '%s',
      '%s'
    ] as [BigNumberish, BigNumberish],
    b: [
      [
        '%s',
        '%s'
      ],
      [
        '%s',
        '%s'
      ]
    ] as [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]],
    c: [
      '%s',
      '%s'
    ] as [BigNumberish, BigNumberish],
    commit: [
      '%s',
      '%s'
    ] as [BigNumberish, BigNumberish],
    pok: [
      '%s',
      '%s'
    ] as [BigNumberish, BigNumberish]
  };
	`, a[0], a[1], b[0][0], b[0][1], b[1][0], b[1][1], c[0], c[1], commitments[0], commitments[1], commitmentPok[0], commitmentPok[1])

	// cheat, generating public committed
	maxNbPublicCommitted := 0
	for _, s := range vk.PublicAndCommitmentCommitted { // iterate over commitments
		maxNbPublicCommitted = utils.Max(maxNbPublicCommitted, len(s))
	}
	commitmentsSerialized := make([]byte, len(vk.PublicAndCommitmentCommitted)*fr.Bytes)
	commitmentPrehashSerialized := make([]byte, curve.SizeOfG1AffineUncompressed+maxNbPublicCommitted*fr.Bytes)
	for i := range vk.PublicAndCommitmentCommitted { // solveCommitmentWire
		copy(commitmentPrehashSerialized, proof.Commitments[i].Marshal())
		offset := curve.SizeOfG1AffineUncompressed
		for j := range vk.PublicAndCommitmentCommitted[i] {
			copy(commitmentPrehashSerialized[offset:], publicWitness[vk.PublicAndCommitmentCommitted[i][j]-1].Marshal())
			offset += fr.Bytes
		}
		if res, err := fr.Hash(commitmentPrehashSerialized[:offset], []byte(constraint.CommitmentDst), 1); err != nil {
			assert.NoError(err)
		} else {
			publicWitness = append(publicWitness, res[0])
			copy(commitmentsSerialized[i*fr.Bytes:], res[0].Marshal())
		}
	}
	var pws []*big.Int
	for _, pw := range publicWitness {
		bi := new(big.Int)
		pws = append(pws, pw.BigInt(bi))
	}
	fmt.Printf("publicWitness with committed %s\n", pws)

	err = groth16.Verify(proof, vk, _publicWitness)
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

	p := proof.(*groth16_bn254.Proof)

	a[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	a[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	b[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	b[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	b[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	b[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	c[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	c[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])

	commitment[0] = new(big.Int)
	commitment[1] = new(big.Int)
	p.Commitments[0].X.BigInt(commitment[0])
	p.Commitments[0].Y.BigInt(commitment[1])
	fmt.Printf("!! ExportProof: commitment %s %s\n", commitment[0], commitment[1])
	return
}
