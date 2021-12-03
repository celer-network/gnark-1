/*
Copyright © 2021 ConsenSys Software Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package plonk

import (
	"math/big"
	"reflect"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/backend/compiled"
)

type SparseR1CS struct {
	frontend.ConstraintSystem

	Constraints []compiled.SparseR1C
}

// initialCapacity has quite some impact on frontend performance, especially on large circuits size
// we may want to add build tags to tune that
func NewSparseR1CS(curveID ecc.ID, backendID backend.ID, initialCapacity ...int) *SparseR1CS {
	capacity := 0
	if len(initialCapacity) > 0 {
		capacity = initialCapacity[0]
	}
	cs := SparseR1CS{
		ConstraintSystem: frontend.ConstraintSystem{

			CS: compiled.CS{
				MDebug: make(map[int]int),
				MHints: make(map[int]compiled.Hint),
			},

			Coeffs:         make([]big.Int, 4),
			CoeffsIDsLarge: make(map[string]int),
			CoeffsIDsInt64: make(map[int64]int, 4),
		},
		Constraints: make([]compiled.SparseR1C, 0, capacity),

		// Counters:          make([]Counter, 0),
	}

	cs.Coeffs[compiled.CoeffIdZero].SetInt64(0)
	cs.Coeffs[compiled.CoeffIdOne].SetInt64(1)
	cs.Coeffs[compiled.CoeffIdTwo].SetInt64(2)
	cs.Coeffs[compiled.CoeffIdMinusOne].SetInt64(-1)

	cs.CoeffsIDsInt64[0] = compiled.CoeffIdZero
	cs.CoeffsIDsInt64[1] = compiled.CoeffIdOne
	cs.CoeffsIDsInt64[2] = compiled.CoeffIdTwo
	cs.CoeffsIDsInt64[-1] = compiled.CoeffIdMinusOne

	// cs.public.variables = make([]Variable, 0)
	// cs.secret.variables = make([]Variable, 0)
	// cs.internal = make([]Variable, 0, capacity)
	cs.Public = make([]string, 0)
	cs.Secret = make([]string, 0)

	cs.CurveID = curveID
	cs.BackendID = backendID

	return &cs
}

// addPlonkConstraint creates a constraint of the for al+br+clr+k=0
func (cs *SparseR1CS) addPlonkConstraint(l, r, o frontend.Variable, cidl, cidr, cidm1, cidm2, cido, k int, debugID ...int) {

	if len(debugID) > 0 {
		cs.MDebug[len(cs.Constraints)-1] = debugID[0]
	}

	_l := l.(compiled.Term)
	_r := r.(compiled.Term)
	_o := o.(compiled.Term)
	_l.SetCoeffID(cidl)
	_r.SetCoeffID(cidr)
	_o.SetCoeffID(cido)

	u := _l
	v := _r
	u.SetCoeffID(cidm1)
	v.SetCoeffID(cidm2)

	cs.Constraints = append(cs.Constraints, compiled.SparseR1C{L: _l, R: _r, O: _o, M: [2]compiled.Term{u, v}, K: k})
}

// newInternalVariable creates a new wire, appends it on the list of wires of the circuit, sets
// the wire's id to the number of wires, and returns it
func (cs *SparseR1CS) newInternalVariable() compiled.Term {
	idx := cs.NbInternalVariables
	cs.NbInternalVariables++
	return compiled.Pack(idx, compiled.CoeffIdOne, compiled.Internal)
}

// NewPublicVariable creates a new Public Variable
func (cs *SparseR1CS) NewPublicVariable(name string) frontend.Variable {
	idx := cs.NbPublicVariables
	cs.Public = append(cs.Public, name)
	cs.NbPublicVariables++
	return compiled.Pack(idx, compiled.CoeffIdOne, compiled.Public)
}

// NewPublicVariable creates a new Secret Variable
func (cs *SparseR1CS) NewSecretVariable(name string) frontend.Variable {
	idx := len(cs.Secret)
	cs.Public = append(cs.Secret, name)
	cs.NbSecretVariables++
	return compiled.Pack(idx, compiled.CoeffIdOne, compiled.Secret)
}

func (cs *SparseR1CS) NewHint(f hint.Function, inputs ...interface{}) frontend.Variable {
	// create resulting wire
	r := cs.newInternalVariable()
	_, vID, _ := r.Unpack()

	// mark hint as unconstrained, for now
	//cs.mHintsConstrained[vID] = false

	// now we need to store the linear expressions of the expected input
	// that will be resolved in the solver
	hintInputs := make([]compiled.LinearExpression, len(inputs))

	// ensure inputs are set and pack them in a []uint64
	for i, in := range inputs {
		switch t := in.(type) {
		case compiled.Term:
			hintInputs[i] = []compiled.Term{t}
		default:
			n := frontend.FromInterface(in)
			id := cs.CoeffID(&n)
			var u compiled.Term
			u.SetCoeffID(id)
			u.SetWireID(-1) // -1 so it is recognized as a constant
		}
	}

	// add the hint to the constraint system
	cs.MHints[vID] = compiled.Hint{ID: hint.UUID(f), Inputs: hintInputs}

	return r
}

var tVariable reflect.Type

func init() {
	tVariable = reflect.ValueOf(struct{ A frontend.Variable }{}).FieldByName("A").Type()
}
