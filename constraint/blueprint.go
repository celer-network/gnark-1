package constraint

import (
	"unsafe"

	"github.com/consensys/gnark/constraint/solver"
)

type Blueprint interface {
	NbInputs() int
	NbConstraints() int
}

type BlueprintSolvable interface {
	Solve(s Solver, calldata []uint32)
}

type BlueprintR1C interface {
	CompressR1C(c *R1C) []uint32
	DecompressR1C(into *R1C, calldata []uint32)
}

type BlueprintSparseR1C interface {
	CompressSparseR1C(c *SparseR1C) []uint32
	DecompressSparseR1C(into *SparseR1C, calldata []uint32)
}

type BlueprintSparseR1CBlock interface {
	CompressBlock()
	DecompressBlock() []SparseR1C
}

type BlueprintHint interface {
	CompressHint(HintMapping) []uint32
	DecompressHint(h *HintMapping, calldata []uint32)
}

type BlueprintGenericHint struct {
}

func (b *BlueprintGenericHint) DecompressHint(h *HintMapping, calldata []uint32) {
	// ignore first call data == nbInputs
	h.HintID = solver.HintID(calldata[1])
	lenInputs := int(calldata[2])
	h.Inputs = make([]LinearExpression, lenInputs)
	h.Outputs = h.Outputs[:0]
	j := 3
	for i := 0; i < lenInputs; i++ {
		n := int(calldata[j]) // len of linear expr
		j++
		for k := 0; k < n; k++ {
			h.Inputs[i] = append(h.Inputs[i], Term{CID: calldata[j], VID: calldata[j+1]})
			j += 2
		}
	}
	for j < len(calldata) {
		h.Outputs = append(h.Outputs, int(calldata[j]))
		j++
	}
}

func (b *BlueprintGenericHint) CompressHint(h HintMapping) []uint32 {
	nbInputs := 1 // storing nb inputs
	nbInputs++    // hintID
	nbInputs++    // len(h.Inputs)
	for i := 0; i < len(h.Inputs); i++ {
		nbInputs++ // len of h.Inputs[i]
		nbInputs += len(h.Inputs[i]) * 2
	}

	nbInputs += len(h.Outputs)

	r := make([]uint32, 0, nbInputs)
	r = append(r, uint32(nbInputs))
	r = append(r, uint32(h.HintID))
	r = append(r, uint32(len(h.Inputs)))

	for _, l := range h.Inputs {
		r = append(r, uint32(len(l)))
		for _, t := range l {
			r = append(r, uint32(t.CoeffID()), uint32(t.WireID()))
		}
	}

	for _, t := range h.Outputs {
		r = append(r, uint32(t))
	}
	if len(r) != nbInputs {
		panic("invalid")
	}
	return r
}

func (b *BlueprintGenericHint) NbInputs() int {
	return -1
}
func (b *BlueprintGenericHint) NbConstraints() int {
	return 0
}

type BlueprintGenericSparseR1C struct {
}

func (b *BlueprintGenericSparseR1C) NbInputs() int {
	return 10 // xa, xb, qL, qR
}
func (b *BlueprintGenericSparseR1C) NbConstraints() int {
	return 1
}

func (b *BlueprintGenericSparseR1C) CompressSparseR1C(c *SparseR1C) []uint32 {
	return []uint32{
		// generic plonk constraint, the wires first
		c.L.VID,
		c.R.VID,
		c.O.VID,
		// coeffs
		c.L.CID,
		c.R.CID,
		c.O.CID,
		c.M[0].CID,
		c.M[1].CID,
		uint32(c.K),
		uint32(c.Commitment),
	}
}

func (b *BlueprintGenericSparseR1C) DecompressSparseR1C(c *SparseR1C, calldata []uint32) {
	c.Clear()

	// calldata := cs.CallData[instruction.StartCallData : instruction.StartCallData+uint32(b.NbInputs())]

	c.L.VID = calldata[0]
	c.R.VID = calldata[1]
	c.O.VID = calldata[2]
	c.L.CID = calldata[3]
	c.R.CID = calldata[4]
	c.O.CID = calldata[5]
	c.M[0].CID = calldata[6]
	c.M[1].CID = calldata[7]
	c.M[0].VID = c.L.VID
	c.M[1].VID = c.R.VID
	c.K = int(calldata[8])
	c.Commitment = CommitmentConstraint(calldata[9])
}

type BlueprintGenericR1C struct {
}

func (b *BlueprintGenericR1C) NbInputs() int {
	return -1
}
func (b *BlueprintGenericR1C) NbConstraints() int {
	return 1
}

func (b *BlueprintGenericR1C) CompressR1C(c *R1C) []uint32 {
	nbInputs := 3 + 2*(len(c.L)+len(c.R)+len(c.O))
	r := make([]uint32, 0, nbInputs)
	r = append(r, uint32(nbInputs))
	r = append(r, uint32(len(c.L)), uint32(len(c.R)))
	for _, t := range c.L {
		r = append(r, uint32(t.CoeffID()), uint32(t.WireID()))
	}
	for _, t := range c.R {
		r = append(r, uint32(t.CoeffID()), uint32(t.WireID()))
	}
	for _, t := range c.O {
		r = append(r, uint32(t.CoeffID()), uint32(t.WireID()))
	}
	return r
}

func (b *BlueprintGenericR1C) DecompressR1C(c *R1C, calldata []uint32) {
	lenL := int(calldata[1])
	lenR := int(calldata[2])
	lenO := int(((calldata[0] - 3) / 2) - uint32(lenL) - uint32(lenR))

	j := 3
	c.L = unsafe.Slice((*Term)(unsafe.Pointer(unsafe.SliceData(calldata[j:j+2*lenL]))), lenL)
	j += 2 * lenL
	c.R = unsafe.Slice((*Term)(unsafe.Pointer(unsafe.SliceData(calldata[j:j+2*lenR]))), lenR)
	j += 2 * lenR
	c.O = unsafe.Slice((*Term)(unsafe.Pointer(unsafe.SliceData(calldata[j:j+2*lenO]))), lenO)
}

// Next steps:
// 2. do the R1CS refactor
// 3. move the hints
// 4. restore parallel solver
// 5. restore debug info ?

type BlueprintSparseR1CMul struct {
}

func (b *BlueprintSparseR1CMul) NbInputs() int {
	return 4
}
func (b *BlueprintSparseR1CMul) NbConstraints() int {
	return 1
}

func (b *BlueprintSparseR1CMul) CompressSparseR1C(c *SparseR1C) []uint32 {
	return []uint32{
		c.M[0].CID,
		c.M[0].VID,
		c.M[1].VID,
		c.O.VID,
	}
}

type Solver interface {
	Field
	GetValue(cID, vID uint32) Element
	GetCoeff(cID uint32) Element
	SetValue(vID uint32, f Element)
}

func (b *BlueprintSparseR1CMul) Solve(s Solver, calldata []uint32) {
	m0 := s.GetValue(calldata[0], calldata[1])
	m1 := s.GetValue(CoeffIdOne, calldata[2])
	// qO := s.GetCoeff(calldata[3])

	m0 = s.Mul(m0, m1)
	// m0.Div(qO)

	s.SetValue(calldata[3], m0)

}

func (b *BlueprintSparseR1CMul) DecompressSparseR1C(c *SparseR1C, calldata []uint32) {
	c.Clear()

	c.M[0].CID = calldata[0]
	c.M[0].VID = calldata[1]
	c.M[1].CID = CoeffIdOne
	c.M[1].VID = calldata[2]
	c.O.CID = CoeffIdMinusOne
	c.O.VID = calldata[3]

	c.L.VID = c.M[0].VID
	c.R.VID = c.M[1].VID
}