package keccaklookup

import (
	"fmt"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func TestXorChi(t *testing.T) {
	c := &TestXorChiCircuit{
		Words: Words{
			parseBinary("1000"),
			parseBinary("0101"),
			parseBinary("1100"),
		},
	}
	w := &TestXorChiCircuit{
		Words: Words{
			parseBinary("1000"),
			parseBinary("0101"),
			parseBinary("1100"),
		},
	}
	err := test.IsSolved(c, w, ecc.BN254.ScalarField())
	check(err)
}

type TestXorChiCircuit struct {
	Words Words `gnark:",public"`
}

func (c *TestXorChiCircuit) Define(api frontend.API) error {
	k := NewKeccakfAPI(api, 4)
	w0 := Words{c.Words[0], c.Words[0]}
	w1 := Words{c.Words[1], c.Words[1]}
	w2 := Words{c.Words[2], c.Words[2]}
	xored := k.xor(w0, w1, w2)
	api.AssertIsEqual(xored[0].Val, parseBinary("0001").Val)
	api.AssertIsEqual(xored[1].Val, parseBinary("0001").Val)
	api.AssertIsEqual(xored[0].Size, 4)
	api.AssertIsEqual(xored[1].Size, 4)

	chi := k.chi(w0, w1, w2)
	api.AssertIsEqual(chi[0].Val, parseBinary("1001").Val)
	api.AssertIsEqual(chi[1].Val, parseBinary("1001").Val)
	api.AssertIsEqual(chi[0].Size, 4)
	api.AssertIsEqual(chi[1].Size, 4)
	return nil
}

func TestPermute(t *testing.T) {
	data, _ := hexutil.Decode("0xff00000000000000000000000000000000000000000000000000000000000010ff")
	hash, _ := hexutil.Decode("0x746cc57064795780b008312042c24f949ad9dc0ee2dce9f4828f5a8869ccecca")

	padded := Pad101Bytes(data)
	paddedBits := Bytes2BlockBits(padded)
	out := Bytes2Bits(hash)
	if len(out) != 256 {
		panic(fmt.Sprintf("out len %d", len(out)))
	}
	var out256 [256]frontend.Variable
	for i, v := range out {
		out256[i] = frontend.Variable(v)
	}
	var dataBits []frontend.Variable
	// convert int array to frontend.Variable array
	for _, b := range paddedBits {
		dataBits = append(dataBits, b)
	}
	// fill the rest with 0s
	zerosToPad := 1088 - len(dataBits)
	for i := 0; i < zerosToPad; i++ {
		dataBits = append(dataBits, 0)
	}

	c := &KeccakCircuit{
		Data: dataBits,
		Out:  out256,
		k:    8,
	}
	// w := &KeccakCircuit{
	// 	Data: dataBits,
	// 	Out:  out256,
	// 	k:    8,
	// }

	// err := test.IsSolved(c, w, ecc.BN254.ScalarField())
	// check(err)

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c, frontend.WithCapacity(1<<24))
	check(err)
	fmt.Println("constraints", cs.GetNbConstraints())
}

type KeccakCircuit struct {
	Data []frontend.Variable    `gnark:",public"`
	Out  [256]frontend.Variable `gnark:",public"`
	k    int                    `gnark:"-"`
}

func (c *KeccakCircuit) Define(api frontend.API) error {
	k := NewKeccakfAPI(api, c.k)
	// prepare input into 17 lanes of words
	var dataWs Words
	for _, b := range c.Data {
		dataWs = append(dataWs, Word{Val: b, Size: 1})
	}
	var in [17]Words
	for i := 0; i < 1088; i += 64 {
		w := k.wa.merge(Words(dataWs[i : i+64]))
		in[i/64] = k.wa.split(w, c.k)
	}
	// prepare empty state
	var s [25]Words
	for i := 0; i < 25; i++ {
		for j := 0; j < 64/c.k; j++ {
			s[i] = append(s[i], Word{Val: 0, Size: c.k})
		}
	}
	// absorb
	for i := range in {
		s[i] = k.xor(s[i], in[i])
	}
	// do permute
	before := time.Now()
	out := k.Permute(s)
	fmt.Printf("permute took %s\n", time.Since(before))
	out = k.Permute(s)
	// convert lanes back into single bit words
	var actual Words
	for i := 0; i < 4; i++ {
		for _, w := range out[i] {
			actual = append(actual, k.wa.split(w, 1)...)
		}
	}
	var expected Words
	for _, b := range c.Out {
		expected = append(expected, Word{Val: b, Size: 1})
	}
	api.AssertIsEqual(len(actual), len(expected))
	for i := range expected {
		api.AssertIsEqual(actual[i].Val, expected[i].Val)
	}
	return nil
}

func Pad101Bytes(data []byte) []byte {
	miss := 136 - len(data)%136
	if len(data)%136 == 0 {
		miss = 136
	}
	data = append(data, 1)
	for i := 0; i < miss-1; i++ {
		data = append(data, 0)
	}
	data[len(data)-1] ^= 0x80
	return data
}

func Bytes2BlockBits(bytes []byte) (bits []uint8) {
	if len(bytes)%136 != 0 {
		panic("invalid length")
	}
	return Bytes2Bits(bytes)
}

func Bytes2Bits(bytes []byte) (bits []uint8) {
	if len(bytes)%8 != 0 {
		panic("invalid length")
	}
	for i := 0; i < len(bytes); i++ {
		bits = append(bits, byte2Bits(bytes[i])...)
	}
	return
}

// bytes2Bits outputs bits in little-endian
func byte2Bits(b byte) (bits []uint8) {
	for i := 0; i < 8; i++ {
		bits = append(bits, (uint8(b)>>i)&1)
	}
	return
}
