package zkpschemes

const Groth16Prove = `

import (
	{{ template "import_curve" . }}
	{{ template "import_backend" . }}
	"runtime"
	"sync"
	"github.com/consensys/gnark/internal/utils/debug"
	"github.com/consensys/gnark/internal/utils/parallel"
	"github.com/consensys/gnark/backend"
)


// Proof represents a Groth16 proof that was encoded with a ProvingKey and can be verified
// with a valid statement and a VerifyingKey
type Proof struct {
	Ar, Krs curve.G1Affine
	Bs      curve.G2Affine
}

var (
	minusTwoInv fr.Element
)

func init() {
	minusTwoInv.SetUint64(2)
	minusTwoInv.Neg(&minusTwoInv).
		Inverse(&minusTwoInv)
}

// Prove creates proof from a circuit
func Prove(r1cs *backend_{{toLower .Curve}}.R1CS, pk *ProvingKey, solution map[string]interface{}) (*Proof, error) {
	proof := &Proof{}

	// fft domain (computeH)
	fftDomain := backend_{{toLower .Curve}}.NewDomain(r1cs.NbConstraints)

	// sample random r and s
	var r, s, kr big.Int
	{
		var _r, _s, _kr fr.Element
		_r.SetRandom()
		_s.SetRandom()
		_kr.Mul(&_r, &_s).Neg(&_kr)

		_r.ToBigIntRegular(&r)
		_s.ToBigIntRegular(&s)
		_kr.ToBigIntRegular(&kr)
	}

	// Solve the R1CS and compute the a, b, c vectors
	wireValues := make([]fr.Element, r1cs.NbWires)
	a := make([]fr.Element, r1cs.NbConstraints, fftDomain.Cardinality) 
	b := make([]fr.Element, r1cs.NbConstraints, fftDomain.Cardinality)
	c := make([]fr.Element, r1cs.NbConstraints, fftDomain.Cardinality)
	err := r1cs.Solve(solution, a, b, c, wireValues)
	if err != nil {
		return nil, err
	}


	// set the wire values in regular form
	for i := 0; i < len(wireValues); i++ {
		wireValues[i].FromMont()
	}
	// preprocess them once for the multiExps (Ar1, Bs1, Bs2)
	processedWireValues := curve.PartitionScalars(wireValues)

	// compute proof elements
	// 4 multiexp + 1 FFT

	// H (witness reduction / FFT part)
	h := computeH(a, b, c, fftDomain)

	// Ar1 (1 multi exp G1 - size = len(wires))
	ar := computeAr1(pk,  processedWireValues)

	// Bs1 (1 multi exp G1 - size = len(wires))
	bs1 := computeBs1(pk, processedWireValues)

	// Krs -- computeKrs go routine will wait for H to be done
	krs := computeKrs(pk,  wireValues, h, r1cs.NbWires-r1cs.NbPublicWires)

	// Bs2 (1 multi exp G2 - size = len(wires))
	proof.Bs = computeBs2(pk, &s, processedWireValues)


	var p1 curve.G1Jac
	p1.ScalarMulGLV (&pk.G1.Delta, &s)
	bs1.AddAssign(&p1)

	p1.ScalarMulGLV (&pk.G1.Delta, &r)
	ar.AddAssign(&p1)



	proof.Ar.FromJacobian(&ar)
	var bs1Affine curve.G1Affine
	bs1Affine.FromJacobian(&bs1)


	p1.ScalarMulGLV(&pk.G1.Delta,& kr)
	krs.AddAssign(&p1)
	p1.ScalarMulGLV(&proof.Ar,& s)
	krs.AddAssign(&p1)
	p1.ScalarMulGLV(&bs1Affine, &r)
	krs.AddAssign(&p1)

	proof.Krs.FromJacobian(&krs)

	return proof, nil
}

func computeKrs(pk *ProvingKey, wireValues []fr.Element, h []fr.Element, kIndex int) curve.G1Jac {
		var Krs curve.G1Jac

		// Krs (H part + priv part)
		points := make([]curve.G1Affine, 0, len(pk.G1.Z) + kIndex + 1)
		points = append(points, pk.G1.Z...)
		points = append(points, pk.G1.K[:kIndex]...)

		scalars := make([]fr.Element,0, len(pk.G1.Z) + kIndex + 3 )
		scalars = append(scalars, h...)
		scalars = append(scalars, wireValues[:kIndex]...)  
		
		Krs.MultiExp( points, scalars)

		return Krs
}

func computeBs2(pk *ProvingKey, s *big.Int, wireValues []fr.Element) curve.G2Affine {

		var Bs, deltaS curve.G2Jac
		var BsAffine curve.G2Affine
		
		Bs.MultiExp(pk.G2.B, wireValues, curve.MultiExpOptions{IsPartitionned: true})
		
		deltaS.ScalarMulGLV( &pk.G2.Delta, s)
		
		Bs.AddAssign(&deltaS)
		
		Bs.AddMixed(&pk.G2.Beta)
		BsAffine.FromJacobian(&Bs)
		return BsAffine
}

func computeBs1(pk *ProvingKey, wireValues []fr.Element) curve.G1Jac {
	
		var bs1 curve.G1Jac

		bs1.MultiExp( pk.G1.B, wireValues, curve.MultiExpOptions{IsPartitionned: true})
		bs1.AddMixed(&pk.G1.Beta)
		
		return bs1
}

func computeAr1(pk *ProvingKey, wireValues []fr.Element) curve.G1Jac {
	
		var ar curve.G1Jac
		ar.MultiExp( pk.G1.A, wireValues, curve.MultiExpOptions{IsPartitionned: true})
		ar.AddMixed(&pk.G1.Alpha)

		return ar 
}

func computeH(a, b, c []fr.Element, fftDomain *backend_{{toLower .Curve}}.Domain) []fr.Element {
		// H part of Krs
		// Compute H (hz=ab-c, where z=-2 on ker X^n+1 (z(x)=x^n-1))
		// 	1 - _a = ifft(a), _b = ifft(b), _c = ifft(c)
		// 	2 - ca = fft_coset(_a), ba = fft_coset(_b), cc = fft_coset(_c)
		// 	3 - h = ifft_coset(ca o cb - cc)

		n := len(a)
		debug.Assert((n == len(b)) && (n == len(c)))

		// add padding
		padding := make([]fr.Element, fftDomain.Cardinality-n)
		a = append(a, padding...)
		b = append(b, padding...)
		c = append(c, padding...)
		n = len(a)

		// exptable = scale by inverse of n + coset
		// ifft(a) would normaly do FFT(a, wInv) then scale by CardinalityInv
		// fft_coset(a) would normaly mutliply a with expTable of fftDomain.GeneratorSqRt
		// this pre-computed expTable do both in one pass --> it contains
		// expTable[0] = fftDomain.CardinalityInv
		// expTable[1] = fftDomain.GeneratorSqrt^1 * fftDomain.CardinalityInv
		// expTable[2] = fftDomain.GeneratorSqrt^2 * fftDomain.CardinalityInv
		// ...
		expTable := make([]fr.Element, n)
		expTable[0] = fftDomain.CardinalityInv

		var wgExpTable sync.WaitGroup

		// to ensure the pool is busy while the FFT splits, we schedule precomputation of the exp table
		// before the FFTs
		asyncExpTable(fftDomain.CardinalityInv, fftDomain.GeneratorSqRt, expTable, &wgExpTable)

		var wg sync.WaitGroup
		FFTa := func(s []fr.Element) {
			// FFT inverse
			backend_{{toLower .Curve}}.FFT(s, fftDomain.GeneratorInv)

			// wait for the expTable to be pre-computed
			// in the nominal case, this is non-blocking as the expTable was scheduled before the FFT
			wgExpTable.Wait()
			parallel.Execute( n, func(start, end int) {
				for i := start; i < end; i++ {
					s[i].MulAssign(&expTable[i])
				}
			})

			// FFT coset
			backend_{{toLower .Curve}}.FFT(s, fftDomain.Generator)
			wg.Done()
		}
		wg.Add(3)
		go FFTa(a)
		go FFTa(b)
		FFTa(c)

		// wait for first step (ifft + fft_coset) to be done
		wg.Wait()

		// h = ifft_coset(ca o cb - cc)
		// reusing a to avoid unecessary memalloc
		parallel.Execute( n, func(start, end int) {
			for i := start; i < end; i++ {
				a[i].Mul(&a[i], &b[i]).
					SubAssign(&c[i]).
					MulAssign(&minusTwoInv)
			}
		})

		// before computing the ifft_coset, we schedule the expTable precompute of the ifft_coset
		// to ensure the pool is busy while the FFT splits
		// similar reasoning as in ifft pass -->
		// expTable[0] = fftDomain.CardinalityInv
		// expTable[1] = fftDomain.GeneratorSqRtInv^1 * fftDomain.CardinalityInv
		// expTable[2] = fftDomain.GeneratorSqRtInv^2 * fftDomain.CardinalityInv
		asyncExpTable(fftDomain.CardinalityInv, fftDomain.GeneratorSqRtInv, expTable, &wgExpTable)

		// ifft_coset
		backend_{{toLower .Curve}}.FFT(a, fftDomain.GeneratorInv)

		wgExpTable.Wait() // wait for pre-computation of exp table to be done
		parallel.Execute( n, func(start, end int) {
			for i := start; i < end; i++ {
				a[i].MulAssign(&expTable[i]).FromMont()
			}
		})

		return a
}

func asyncExpTable(scale, w fr.Element, table []fr.Element, wg *sync.WaitGroup) {
	n := len(table)

	// see if it makes sense to parallelize exp tables pre-computation
	interval := (n - 1) / runtime.NumCPU()
	// this ratio roughly correspond to the number of multiplication one can do in place of a Exp operation
	const ratioExpMul = 2400 / 26

	if interval < ratioExpMul {
		wg.Add(1)
		go func() {
			precomputeExpTableChunk(scale, w, 1, table[1:])
			wg.Done()
		}()
	} else {
		// we parallelize
		for i := 1; i < n; i += interval {
			start := i
			end := i + interval
			if end > n {
				end = n
			}
			wg.Add(1)
			go func() {
				precomputeExpTableChunk(scale, w, uint64(start), table[start:end])
				wg.Done()
			}()
		}
	}
}

func precomputeExpTableChunk(scale, w fr.Element, power uint64, table []fr.Element) {
	table[0].Exp(w, new(big.Int).SetUint64(power))
	table[0].MulAssign(&scale)
	for i := 1; i < len(table); i++ {
		table[i].Mul(&table[i-1], &w)
	}
}


`
