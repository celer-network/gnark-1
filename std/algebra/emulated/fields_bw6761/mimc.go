package fields_bw6761

import (
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"math/big"
)

// MiMC contains the params of the Mimc hash func and the curves on which it is implemented
type MiMC struct {
	params []big.Int                             // slice containing constants for the encryption rounds
	h      emulated.Element[emulated.BW6761Fr]   // current vector in the Miyaguchi–Preneel scheme
	data   []emulated.Element[emulated.BW6761Fr] // state storage. data is updated when Write() is called. Sum sums the data.
	fp     emulated.Field[emulated.BW6761Fr]
}

func NewMiMC(api frontend.API) MiMC {
	fp, err := emulated.NewField[emulated.BW6761Fr](api)
	if err != nil {
		panic(err)
	}
	res := MiMC{}
	res.params = bw6761.GetConstants()
	res.h = emulated.ValueOf[emulated.BW6761Fr](0)
	res.fp = *fp
	return res
}

func (h *MiMC) encryptPow5(m emulated.Element[emulated.BW6761Fr]) emulated.Element[emulated.BW6761Fr] {
	x := m
	for i := 0; i < len(h.params); i++ {
		tmp := h.fp.Add(&x, &h.h)
		k := emulated.ValueOf[emulated.BW6761Fr](h.params[i])
		//m = (m+k+c)^5
		tmp = h.fp.Add(tmp, &k)
		x = h.pow5(tmp)
	}
	return *h.fp.Add(&x, &h.h)

}

func (h *MiMC) pow5(x *emulated.Element[emulated.BW6761Fr]) emulated.Element[emulated.BW6761Fr] {
	r := h.fp.MulMod(x, x)
	s := h.fp.MulMod(r, r)
	return *h.fp.MulMod(s, x)
}

func (h *MiMC) Write(data ...emulated.Element[emulated.BW6761Fr]) {
	h.data = append(h.data, data...)
}

func (h *MiMC) Reset() {
	h.data = nil
	h.h = emulated.ValueOf[emulated.BW6761Fr](0)
}

func (h *MiMC) Sum() emulated.Element[emulated.BW6761Fr] {
	for _, stream := range h.data {
		r := h.encryptPow5(stream)
		temp := h.fp.Add(&h.h, &r)
		h.h = *h.fp.Add(temp, &stream)
	}
	return h.h
}
