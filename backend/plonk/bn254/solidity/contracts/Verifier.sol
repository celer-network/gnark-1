// Warning this code was contributed into gnark here: 
// https://github.com/ConsenSys/gnark/pull/358
// 
// It has not been audited and is provided as-is, we make no guarantees or warranties to its safety and reliability. 
// 
// According to https://eprint.iacr.org/archive/2019/953/1585767119.pdf
pragma solidity ^0.8.0;

import {Bn254} from './crypto/Bn254.sol';
import {Fr} from './crypto/Fr.sol';
import {TranscriptLibrary} from './crypto/Transcript.sol';
import {Polynomials} from './crypto/Polynomials.sol';
import {Types} from './crypto/Types.sol';
import {Kzg} from './crypto/Kzg.sol';

// contract PlonkVerifier {
library PlonkVerifier{

    using Bn254 for Bn254.G1Point;
    using Bn254 for Bn254.G2Point;
    using Fr for uint256;
    using TranscriptLibrary for TranscriptLibrary.Transcript;
    using Polynomials for *;
    using Types for *;

    uint256 constant STATE_WIDTH = 3;

    event PrintUint256(uint256 a);
    event PrintBool(bool a);

    function derive_gamma_beta_alpha_zeta(

        Types.PartialVerifierState memory state,
        Types.Proof memory proof,
        Types.VerificationKey memory vk,
        uint256[] memory public_inputs) internal pure {

        TranscriptLibrary.Transcript memory t = TranscriptLibrary.new_transcript();
        t.set_challenge_name("gamma");

        for (uint256 i = 0; i < vk.permutation_commitments.length; i++) {
            t.update_with_g1(vk.permutation_commitments[i]);
        }
       
        t.update_with_g1(vk.selector_commitments[0]); // ql
        t.update_with_g1(vk.selector_commitments[1]); // qr
        t.update_with_g1(vk.selector_commitments[2]); // qm
        t.update_with_g1(vk.selector_commitments[3]); // qo
        t.update_with_g1(vk.selector_commitments[4]); // qk

        for (uint256 i = 0; i < public_inputs.length; i++) {
            t.update_with_u256(public_inputs[i]);
        }

        t.update_with_g1(proof.wire_commitments[3]); // PI2
        t.update_with_g1(proof.wire_commitments[0]); // [L]
        t.update_with_g1(proof.wire_commitments[1]); // [R]
        t.update_with_g1(proof.wire_commitments[2]); // [O]

        state.gamma = t.get_challenge();

        t.set_challenge_name("beta");
        state.beta = t.get_challenge();

        t.set_challenge_name("alpha");
        t.update_with_g1(proof.grand_product_commitment);
        state.alpha = t.get_challenge();

        t.set_challenge_name("zeta");
        for (uint256 i = 0; i < proof.quotient_poly_commitments.length; i++) {
            t.update_with_g1(proof.quotient_poly_commitments[i]);
        }
        state.zeta = t.get_challenge();
    }

     // plonk paper verify process step8: Compute quotient polynomial evaluation
    function verify_quotient_poly_eval_at_zeta(
        Types.PartialVerifierState memory state,
        Types.Proof memory proof,
        Types.VerificationKey memory vk,
        uint256[] memory public_inputs
    ) internal view returns (bool) {

        // evaluation of Z=Xⁿ⁻¹ at ζ
        uint256 zeta_power_n_minus_one = Fr.pow(state.zeta, vk.domain_size);
        zeta_power_n_minus_one = Fr.sub(zeta_power_n_minus_one, 1);

        // compute PI = ∑_{i<n} Lᵢ*wᵢ
        uint256 pi = Polynomials.compute_sum_li_zi_batch(public_inputs, state.zeta, vk.omega, vk.domain_size);
        // TODO Inject commitment value as well

        uint256 _s1;
        _s1 = Fr.mul(proof.permutation_polynomials_at_zeta[0], state.beta);
        _s1 = Fr.add(_s1, state.gamma);
        _s1 = Fr.add(_s1, proof.wire_values_at_zeta[0]);  // (l(ζ)+β*s1(ζ)+γ)

        uint256 _s2;
        _s2 = Fr.mul(proof.permutation_polynomials_at_zeta[1], state.beta);
        _s2 = Fr.add(_s2, state.gamma);
        _s2 = Fr.add(_s2, proof.wire_values_at_zeta[1]); // (r(ζ)+β*s2(ζ)+γ)

        uint256 _o;
        _o = Fr.add(proof.wire_values_at_zeta[2], state.gamma);  // (o(ζ)+γ)

        _s1 = Fr.mul(_s1, _s2);
        _s1 = Fr.mul(_s1, _o);
        _s1 = Fr.mul(_s1, state.alpha);
        _s1 = Fr.mul(_s1, proof.grand_product_at_zeta_omega); //  α*(Z(μζ))*(l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*(o(ζ)+γ)

        state.alpha_square_lagrange = Polynomials.compute_ith_lagrange_at_z(0, state.zeta, vk.omega, vk.domain_size);
        state.alpha_square_lagrange = Fr.mul(state.alpha_square_lagrange, state.alpha);
        state.alpha_square_lagrange = Fr.mul(state.alpha_square_lagrange, state.alpha);  // α²*L₁(ζ)
        
        uint256 compute_quotient;
        compute_quotient = Fr.add(proof.linearization_polynomial_at_zeta, pi); // linearizedpolynomial + pi(zeta)
        compute_quotient = Fr.add(compute_quotient, _s1); // linearizedpolynomial+pi(zeta)+α*(Z(μζ))*(l(ζ)+s1(ζ)+γ)*(r(ζ)+s2(ζ)+γ)*(o(ζ)+γ)
        compute_quotient = Fr.sub(compute_quotient, state.alpha_square_lagrange); // linearizedpolynomial+pi(zeta)+α*(Z(μζ))*(l(ζ)+s1(ζ)+γ)*(r(ζ)+s2(ζ)+γ)*(o(ζ)+γ)-α²*L₁(ζ)

        // Compute H(ζ) using the previous result: H(ζ) = prev_result/(ζⁿ-1)
        compute_quotient = Fr.div(compute_quotient, zeta_power_n_minus_one);
        
        return compute_quotient == proof.quotient_polynomial_at_zeta;
    }

    function fold_h(
        Types.PartialVerifierState memory state,
        Types.Proof memory proof,
        Types.VerificationKey memory vk
    ) internal view {

        // folded_h = Comm(h₁) + ζᵐ⁺²*Comm(h₂) + ζ²⁽ᵐ⁺²⁾*Comm(h₃)
        uint256 n_plus_two = Fr.add(vk.domain_size, 2);
        uint256 zeta_power_n_plus_two = Fr.pow(state.zeta, n_plus_two);
        state.folded_h = proof.quotient_poly_commitments[2];
        state.folded_h.point_mul_assign(zeta_power_n_plus_two);
        state.folded_h.point_add_assign(proof.quotient_poly_commitments[1]);
        state.folded_h.point_mul_assign(zeta_power_n_plus_two);
        state.folded_h.point_add_assign(proof.quotient_poly_commitments[0]);
    }

    function compute_commitment_linearised_polynomial(
        Types.PartialVerifierState memory state,
        Types.Proof memory proof,
        Types.VerificationKey memory vk
    ) internal view {

        // linearizedPolynomialDigest =
        // 		l(ζ)*ql+r(ζ)*qr+r(ζ)l(ζ)*qm+o(ζ)*qo+qk+qc*PI2 +
        // 		α*( Z(μζ)(l(ζ)+β*s₁(ζ)+γ)*(r(ζ)+β*s₂(ζ)+γ)*s₃(X)-Z(X)(l(ζ)+β*id_1(ζ)+γ)*(r(ζ)+β*id_2(ζ)+γ)*(o(ζ)+β*id_3(ζ)+γ) ) +
        // 		α²*L₁(ζ)*Z

        // α*( Z(μζ)(l(ζ)+β*s₁(ζ)+γ)*(r(ζ)+β*s₂(ζ)+γ)*β*s₃(X)-Z(X)(l(ζ)+β*id_1(ζ)+γ)*(r(ζ)+β*id_2(ζ)+γ)*(o(ζ)+β*id_3(ζ)+γ) ) )
        uint256 u;
        uint256 v;
        uint256 w;
        u = Fr.mul(proof.grand_product_at_zeta_omega, state.beta);
        v = Fr.mul(state.beta, proof.permutation_polynomials_at_zeta[0]);
        v = Fr.add(v, proof.wire_values_at_zeta[0]);
        v = Fr.add(v, state.gamma);

        w = Fr.mul(state.beta, proof.permutation_polynomials_at_zeta[1]);
        w = Fr.add(w, proof.wire_values_at_zeta[1]);
        w = Fr.add(w, state.gamma);

        uint256 _s1;
        _s1 = Fr.mul(u, v);
        _s1 = Fr.mul(_s1, w);
        _s1 = Fr.mul(_s1, state.alpha); // α*Z(μζ)(l(ζ)+β*s₁(ζ)+γ)*(r(ζ)+β*s₂(ζ)+γ)*β

        uint256 coset_square = Fr.mul(vk.coset_shift, vk.coset_shift);
        uint256 betazeta = Fr.mul(state.beta, state.zeta);
        u = Fr.add(betazeta, proof.wire_values_at_zeta[0]);
        u = Fr.add(u, state.gamma); // (l(ζ)+β*ζ+γ)

        v = Fr.mul(betazeta, vk.coset_shift);
        v = Fr.add(v, proof.wire_values_at_zeta[1]);
        v = Fr.add(v, state.gamma); // (r(ζ)+β*μ*ζ+γ)

        w = Fr.mul(betazeta, coset_square);
        w = Fr.add(w, proof.wire_values_at_zeta[2]);
        w = Fr.add(w, state.gamma); // (o(ζ)+β*μ²*ζ+γ)

        uint256 _s2 = Fr.mul(u, v);
        _s2 = Fr.mul(_s2, w);
        _s2 = Fr.sub(0, _s2);  // -(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)
        _s2 = Fr.mul(_s2, state.alpha);
        _s2 = Fr.add(_s2, state.alpha_square_lagrange); // -α*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ) + α²*L₁(ζ)

        uint256 rl =  Fr.mul(proof.wire_values_at_zeta[0], proof.wire_values_at_zeta[1]);

        // multi exp part
        state.linearised_polynomial = Bn254.point_mul(vk.selector_commitments[0], proof.wire_values_at_zeta[0]);
        Bn254.G1Point memory ptmp = Bn254.point_mul(vk.selector_commitments[1], proof.wire_values_at_zeta[1]);
        state.linearised_polynomial = Bn254.point_add(state.linearised_polynomial, ptmp);

        ptmp = Bn254.point_mul(vk.selector_commitments[2], rl);
        state.linearised_polynomial = Bn254.point_add(state.linearised_polynomial, ptmp);

        ptmp = Bn254.point_mul(vk.selector_commitments[3], proof.wire_values_at_zeta[2]);
        state.linearised_polynomial = Bn254.point_add(state.linearised_polynomial, ptmp);

        state.linearised_polynomial = Bn254.point_add(state.linearised_polynomial, vk.selector_commitments[4]);

        ptmp = Bn254.point_mul(proof.wire_commitments[3], proof.qcprime_at_zeta);
        state.linearised_polynomial = Bn254.point_add(state.linearised_polynomial, ptmp);

        ptmp = Bn254.point_mul(vk.permutation_commitments[2], _s1);
        state.linearised_polynomial = Bn254.point_add(state.linearised_polynomial, ptmp);

        ptmp = Bn254.point_mul(proof.grand_product_commitment, _s2);
        state.linearised_polynomial = Bn254.point_add(state.linearised_polynomial, ptmp);

    }

    function fold_state(
        Types.PartialVerifierState memory state,
        Types.Proof memory proof,
        Types.VerificationKey memory vk
    ) internal view{

        Bn254.G1Point[] memory digests = new Bn254.G1Point[](8);
        digests[0] = state.folded_h;
        digests[1] = state.linearised_polynomial;
        digests[2] = proof.wire_commitments[0];
        digests[3] = proof.wire_commitments[1];
        digests[4] = proof.wire_commitments[2];
        digests[5] = vk.permutation_commitments[0];
        digests[6] = vk.permutation_commitments[1];
        digests[7] = vk.selector_commitments[5];

        // TODO perhaps we should we inline all this
        Kzg.BatchOpeningProof memory batch_opening_proof;
        batch_opening_proof.H = proof.opening_at_zeta_proof;
        batch_opening_proof.claimed_values = new uint256[](8);
        batch_opening_proof.claimed_values[0] = proof.quotient_polynomial_at_zeta;
        batch_opening_proof.claimed_values[1] = proof.linearization_polynomial_at_zeta;
        batch_opening_proof.claimed_values[2] = proof.wire_values_at_zeta[0];
        batch_opening_proof.claimed_values[3] = proof.wire_values_at_zeta[1];
        batch_opening_proof.claimed_values[4] = proof.wire_values_at_zeta[2];
        batch_opening_proof.claimed_values[5] = proof.permutation_polynomials_at_zeta[0];
        batch_opening_proof.claimed_values[6] = proof.permutation_polynomials_at_zeta[1];
        batch_opening_proof.claimed_values[7] = proof.qcprime_at_zeta;

        (state.folded_proof, state.folded_digests) = Kzg.fold_proof(
            digests, 
            batch_opening_proof, 
            state.zeta);  
        
    } 

    function verify(Types.Proof memory proof, Types.VerificationKey memory vk, uint256[] memory public_inputs)
    internal view returns (bool) {
        
        Types.PartialVerifierState memory state;
        
        // step 1: derive gamma, beta, alpha, delta
        derive_gamma_beta_alpha_zeta(state, proof, vk, public_inputs);

        // step 2: verifiy the claimed quotient
        bool valid = verify_quotient_poly_eval_at_zeta(state, proof, vk, public_inputs);

        // step 3: fold H ( = Comm(h₁) + ζᵐ⁺²*Comm(h₂) + ζ²⁽ᵐ⁺²⁾*Comm(h₃))
        fold_h(state, proof, vk);

        // linearizedPolynomialDigest =
        // 		l(ζ)*ql+r(ζ)*qr+r(ζ)l(ζ)*qm+o(ζ)*qo+qk+qc*PI2 +
        // 		α*( Z(μζ)(l(ζ)+β*s₁(ζ)+γ)*(r(ζ)+β*s₂(ζ)+γ)*s₃(X)-Z(X)(l(ζ)+β*id_1(ζ)+γ)*(r(ζ)+β*id_2(ζ)+γ)*(o(ζ)+β*id_3(ζ)+γ) ) +
        // 		α²*L₁(ζ)*Z
        compute_commitment_linearised_polynomial(state, proof, vk);

        // step 4: fold proof + digests 
        fold_state(state, proof, vk);

        // step 5: batch verify the folded proof and the opening proof at omega*zeta
        Bn254.G1Point[] memory digests = new Bn254.G1Point[](2);
        digests[0] = state.folded_digests;
        digests[1] = proof.grand_product_commitment;
        
        Kzg.OpeningProof[] memory proofs = new Kzg.OpeningProof[](2);
        proofs[0] = state.folded_proof;
        proofs[1].H = proof.opening_at_zeta_omega_proof;
        proofs[1].claimed_value = proof.grand_product_at_zeta_omega;

        uint256[] memory points = new uint256[](2);
        points[0] = state.zeta;
        points[1] = Fr.mul(state.zeta, vk.omega);

        valid = valid && Kzg.batch_verify_multi_points(digests, proofs, points, vk.g2_x);

        return valid;
    }
}

