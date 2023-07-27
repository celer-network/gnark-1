package fields_bw6761

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	fr "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"github.com/consensys/gnark/frontend"
	mimc2 "github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"math"
	"math/big"
	"testing"
)

type MiMCTestCircuit struct {
	PreImage frontend.Variable
	Hash     frontend.Variable
}

func (c *MiMCTestCircuit) Define(api frontend.API) error {
	miMC, err := mimc2.NewMiMC(api)
	miMC.Write(c.PreImage)
	out := miMC.Sum()
	api.AssertIsEqual(out, c.Hash)
	return err
}

func TestMiMC(t *testing.T) {
	assert := test.NewAssert(t)

	var one = 1
	var buffer = make([]byte, mimc.BlockSize)
	buffer[mimc.BlockSize-1] = 1
	hash := mimc.NewMiMC()
	hash.Write(buffer)
	res := hash.Sum(nil)

	var witness, circuit MiMCTestCircuit
	witness.PreImage = one
	witness.Hash = res

	err := test.IsSolved(&circuit, &witness, ecc.BW6_761.ScalarField())
	assert.NoError(err)
}

type NoneNativeMiMCTestCircuit struct {
	PreImage emulated.Element[emulated.BW6761Fr]
	Hash     emulated.Element[emulated.BW6761Fr]
}

func (c *NoneNativeMiMCTestCircuit) Define(api frontend.API) error {
	miMC := NewMiMC(api)
	miMC.Write(c.PreImage)
	out := miMC.Sum()
	miMC.fp.AssertIsEqual(&out, &c.Hash)
	return nil
}

func TestNonNativeMiMC(t *testing.T) {
	assert := test.NewAssert(t)

	var one = 1
	var buffer = make([]byte, mimc.BlockSize)
	buffer[mimc.BlockSize-1] = 1
	hash := mimc.NewMiMC()
	hash.Write(buffer)
	res := hash.Sum(nil)

	var witness, circuit NoneNativeMiMCTestCircuit
	witness.PreImage = emulated.ValueOf[emulated.BW6761Fr](one)
	witness.Hash = emulated.ValueOf[emulated.BW6761Fr](res)

	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type MiMCConstMulTestCircuit struct {
	PreImage emulated.Element[emulated.BW6761Fr]
	Out      emulated.Element[emulated.BW6761Fr]
}

func (c *MiMCConstMulTestCircuit) Define(api frontend.API) error {
	fp, err := emulated.NewField[emulated.BW6761Fr](api)
	if err != nil {
		fmt.Println("err:", err)
	}
	res := fp.MulMod(&c.PreImage, &c.PreImage)
	fp.AssertIsEqual(res, &c.Out)
	return nil
}

func TestMiMCConstantsMul(t *testing.T) {
	//consts := mimc.GetConstants()
	const0 := new(big.Int).SetUint64(math.MaxInt64)
	var tmp fr.Element

	tmp.SetBigInt(const0)
	//tmp.Square(&tmp)
	tmp.Mul(&tmp, &tmp)
	res := tmp.Bytes()

	var witness, circuit MiMCConstMulTestCircuit

	witness.PreImage = emulated.ValueOf[emulated.BW6761Fr](const0)
	witness.Out = emulated.ValueOf[emulated.BW6761Fr](res[:])

	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())

	assert := test.NewAssert(t)
	assert.NoError(err)
}
