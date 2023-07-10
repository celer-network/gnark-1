package keccaklookup

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

type Word struct {
	Val  frontend.Variable `json:"val,omitempty"`
	Size int               `json:"size,omitempty"`
}

type Words []Word

func (ws Words) Values() []frontend.Variable {
	var ret []frontend.Variable
	for _, w := range ws {
		ret = append(ret, w.Val)
	}
	return ret
}

func (ws Words) String() string {
	var strs []string
	for _, w := range ws {
		strs = append(strs, fmt.Sprintf("%x", w.Val))
	}
	return strings.Join(strs, "")
}

func (ws Words) totalSize() int {
	var total int
	for _, w := range ws {
		total += w.Size
	}
	return total
}

type wordapi struct {
	api frontend.API
}

func newWordAPI(api frontend.API) *wordapi {
	return &wordapi{api: api}
}

// split splits the word into parts of `partSize` execept the last element.
// this function uses a hint function to compute the split results, then constrains the sum.
// nbParts is the number of equal sized parts of `partSize`. optional, if not specified, the word is split into as many
// `partSize` chunks as possible.
// e.g. for word 1010 if `partSize = 1` and `nbPartsOpt = 2` then the result is [1, 0, 10]
func (wa *wordapi) split(w Word, partSize int, nbPartsOpt ...int) Words {
	if len(nbPartsOpt) > 1 {
		panic(fmt.Sprintf("invalid nbPartsOpt"))
	}
	nbParts := w.Size / partSize
	if len(nbPartsOpt) == 1 {
		nbParts = nbPartsOpt[0]
	}
	if nbParts <= 0 || nbParts > w.Size {
		panic(fmt.Sprintf("cannot split word of size %d into %d parts", w.Size, nbParts))
	}
	remSize := w.Size - nbParts*partSize
	nbTotal := nbParts
	if remSize > 0 {
		nbTotal++
	}
	out, err := wa.api.Compiler().NewHint(genSplitHint(w.Size, partSize, nbParts), nbTotal, w.Val)
	if err != nil {
		panic(fmt.Sprintf("hint failed to split merge output: %s", err.Error()))
	}
	var ret Words
	var acc frontend.Variable = 0
	nbZeros := w.Size
	for i := 0; i < nbParts; i++ {
		nbZeros -= partSize
		acc = wa.api.MulAcc(acc, out[i], exp2(nbZeros))
		ret = append(ret, Word{Val: out[i], Size: partSize})
	}
	if remSize > 0 {
		acc = wa.api.Add(acc, out[len(out)-1])
		ret = append(ret, Word{Val: out[len(out)-1], Size: remSize})
	}
	wa.api.AssertIsEqual(acc, w.Val)
	return ret
}

func (wa *wordapi) merge(ws Words) Word {
	if len(ws) < 1 {
		panic("cannot merge words with length less than 1")
	}
	var acc frontend.Variable = 0
	totalSize := ws.totalSize()
	nbZeros := totalSize
	for i := range ws {
		nbZeros -= ws[i].Size
		acc = wa.api.MulAcc(acc, ws[i].Val, exp2(nbZeros))
	}
	return Word{
		Val:  acc,
		Size: ws.totalSize(),
	}
}

func (wa *wordapi) lrot(ws Words, amount, partSize int) Words {
	rotated := wa.lrotMerge(ws, amount)
	return wa.split(rotated, partSize)
}

func (wa *wordapi) lrotMerge(ws Words, amount int) Word {
	i := 0
	rem := amount
	// search for where to split the word
	for ; i < len(ws); i++ {
		w := ws[i]
		if rem < w.Size {
			break
		}
		rem -= w.Size
	}

	// rotate the slice without splitting first
	rotated := make(Words, len(ws))
	copy(rotated[len(ws)-i:], ws[:i])
	copy(rotated, ws[i:])

	// split if needed
	if rem > 0 {
		parts := wa.split(ws[i], rem, 1)
		// sanity check
		if len(parts) != 2 {
			panic(fmt.Sprintf("invalid parts len %d", len(parts)))
		}
		rotated = append(rotated, parts[0])
		rotated[0] = parts[1]
	}
	return wa.merge(rotated)
}

func exp2(num int) *big.Int {
	base := big.NewInt(2)
	exp := big.NewInt(int64(num))
	return new(big.Int).Exp(base, exp, nil)
}

func genSplitHint(inputSize, partSize, nbParts int) solver.Hint {
	return func(_ *big.Int, inputs, outputs []*big.Int) error {
		if len(inputs) != 1 {
			return fmt.Errorf("split hint requires exactly 1 input param")
		}
		rem := inputs[0]
		remSize := inputSize
		for i := 0; i < nbParts; i++ {
			remSize -= partSize
			zeros := exp2(remSize)
			quo := new(big.Int).Div(rem, zeros)
			outputs[i] = quo
			rem = new(big.Int).Sub(rem, new(big.Int).Mul(quo, zeros))
		}
		if remSize > 0 {
			outputs[len(outputs)-1] = rem
		}
		return nil
	}
}

func constWords64(in uint64, k int) Words {
	var reversed uint64
	for i := 0; i < 64; i++ {
		d := ((in >> (63 - i)) & 1) << i
		reversed += d
	}
	num := new(big.Int).SetUint64(reversed)
	return split(num, 64, k)
}

func split(in *big.Int, inputSize, partSize int) Words {
	var outputs Words
	rem := new(big.Int).Set(in)
	remSize := inputSize
	nbParts := inputSize / partSize
	for i := 0; i < nbParts; i++ {
		remSize -= partSize
		zeros := exp2(remSize)
		quo := new(big.Int).Div(rem, zeros)
		outputs = append(outputs, Word{Val: quo, Size: partSize})
		rem = new(big.Int).Sub(rem, new(big.Int).Mul(quo, zeros))
	}
	if remSize > 0 {
		outputs = append(outputs, Word{Val: rem, Size: remSize})
	}
	return outputs
}
