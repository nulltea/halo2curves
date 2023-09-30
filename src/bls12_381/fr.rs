#[cfg(feature = "asm")]
use super::assembly::assemblyfield;

use super::LegendreSymbol;
use crate::arithmetic::{adc, mac, macx, sbb};
use core::convert::TryInto;
use core::fmt;
use core::ops::{Add, Mul, Neg, Sub};
use ff::{PrimeField, WithSmallOrderMulGroup};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use crate::{
    field_arithmetic, field_common, field_specific, impl_add_binop_specify_output,
    impl_binops_additive, impl_binops_additive_specify_output, impl_binops_multiplicative,
    impl_binops_multiplicative_mixed, impl_sub_binop_specify_output, impl_from_u64, field_bits, impl_sum_prod,
};

/// This represents an element of $\mathbb{F}r$ where
///
/// `r = 52435875175126190479447740508185965837690552500527637822603658699938581184513`
/// `r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`
///
/// is the scalar field of the BLS12-381 curve.
// The internal representation of this type is four 64-bit unsigned
// integers in little-endian order. `Fr` values are always in
// Montgomery form; i.e., Fr(a) = aR mod r, with R = 2^256.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Fr(pub(crate) [u64; 4]);

/// Constant representing the modulus
/// r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
const MODULUS: Fr = Fr([
    0xffffffff00000001,
    0x53bda402fffe5bfe,
    0x3339d80809a1d805,
    0x73eda753299d7d48,
]);

// The number of bits needed to represent the modulus.
const MODULUS_BITS: u32 = 255;

const MODULUS_STR: &str = "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";

/// INV = -(r^{-1} mod 2^64) mod 2^64
const INV: u64 = 0xfffffffeffffffff;

/// `R = 2^256 mod r`
/// `0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe`
const R: Fr = Fr([
    0x1fffffffe,
    0x5884b7fa00034802,
    0x998c4fefecbc4ff5,
    0x1824b159acc5056f,
]);

/// `R^2 = 2^512 mod r`
/// `0x748d9d99f59ff1105d314967254398f2b6cedcb87925c23c999e990f3f29c6d`
const R2: Fr = Fr([
    0xc999e990f3f29c6d,
    0x2b6cedcb87925c23,
    0x5d314967254398f,
    0x748d9d99f59ff11,
]);

/// `R^3 = 2^768 mod r`
/// `0x6e2a5bb9c8db33e973d13c71c7b5f4181b3e0d188cf06990c62c1807439b73af`
const R3: Fr = Fr([
    0xc62c1807439b73af,
    0x1b3e0d188cf06990,
    0x73d13c71c7b5f418,
    0x6e2a5bb9c8db33e9,
]);

/// `GENERATOR = 7 mod r` is a generator of the `r - 1` order multiplicative
/// subgroup, or in other words a primitive root of the field.
const GENERATOR: Fr = Fr::from_raw([
    0xefffffff1,
    0x17e363d300189c0f,
    0xff9c57876f8457b0,
    0x351332208fc5a8c4,
]);

// 2^s * t = MODULUS - 1 with t odd
const S: u32 = 32;

/// GENERATOR^t where t * 2^s + 1 = r
/// with t odd. In other words, this
/// is a 2^s root of unity.
/// `0x5bf3adda19e9b27baf53ae352a31e645b1b4c801819d7ecb9b58d8c5f0e466a`
const ROOT_OF_UNITY: Fr = Fr([
    0xb9b58d8c5f0e466a,
    0x5b1b4c801819d7ec,
    0xaf53ae352a31e64,
    0x5bf3adda19e9b27b,
]);

/// 1 / 2 mod r
/// 0x0c1258acd66282b7ccc627f7f65e27faac425bfd0001a40100000000ffffffff
const TWO_INV: Fr = Fr([
    0x00000000ffffffff,
    0xac425bfd0001a401,
    0xccc627f7f65e27fa,
    0x0c1258acd66282b7,
]);

/// 1 / ROOT_OF_UNITY mod r
/// 0x2d2fc049658afd43f9c3f1d75f7a3b2745f37b7f96b6cad34256481adcf3219a
const ROOT_OF_UNITY_INV: Fr = Fr([
    0x4256481adcf3219a,
    0x45f37b7f96b6cad3,
    0xf9c3f1d75f7a3b27,
    0x2d2fc049658afd43,
]);

/// GENERATOR^{2^s} where t * 2^s + 1 = r
/// with t odd. In other words, this
/// is a t root of unity.
// 0x6185d06627c067cb51e114186a8b970d4b64c08919e299e670e310d3d146f96a
const DELTA: Fr = Fr([
    0x70e310d3d146f96a,
    0x4b64c08919e299e6,
    0x51e114186a8b970d,
    0x6185d06627c067cb,
]);

// Unused constant
const ZETA: Fr = Fr::zero();

impl_binops_additive!(Fr, Fr);
impl_binops_multiplicative!(Fr, Fr);
#[cfg(not(feature = "asm"))]
field_common!(
    Fr,
    MODULUS,
    INV,
    MODULUS_STR,
    TWO_INV,
    ROOT_OF_UNITY_INV,
    DELTA,
    ZETA,
    R,
    R2,
    R3
);

impl_sum_prod!(Fr);
prime_field_legendre!(Fr);
impl_from_u64!(Fr, R2);

#[cfg(not(feature = "asm"))]
field_arithmetic!(Fr, MODULUS, INV, sparse);
#[cfg(feature = "asm")]
assembly_field!(
    Fr,
    MODULUS,
    INV,
    MODULUS_STR,
    TWO_INV,
    ROOT_OF_UNITY_INV,
    DELTA,
    ZETA,
    R,
    R2,
    R3
);
#[cfg(target_pointer_width = "64")]
field_bits!(Fr, MODULUS);

impl Fr {
    fn legendre(&self) -> LegendreSymbol {
        // s = self^((r - 1) // 2)
        let s = self.pow(&[
            0x7fffffff80000000,
            0xa9ded2017fff2dff,
            0x199cec0404d0ec02,
            0x39f6d3a994cebea4,
        ]);
        if s == Self::zero() {
            LegendreSymbol::Zero
        } else if s == Self::one() {
            LegendreSymbol::QuadraticResidue
        } else {
            LegendreSymbol::QuadraticNonResidue
        }
    }

    fn pow(&self, by: &[u64; 4]) -> Self {
        let mut res = Self::one();
        for e in by.iter().rev() {
            for i in (0..64).rev() {
                res = res.square();
                let mut tmp = res;
                tmp *= self;
                res.conditional_assign(&tmp, (((*e >> i) & 0x1) as u8).into());
            }
        }
        res
    }
}

impl ff::Field for Fr {
    const ZERO: Self = Self::zero();
    const ONE: Self = Self::one();

    fn random(mut rng: impl RngCore) -> Self {
        Self::from_u512([
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
        ])
    }

    fn double(&self) -> Self {
        self.double()
    }

    fn is_zero_vartime(&self) -> bool {
        self == &Self::zero()
    }

    #[inline(always)]
    fn square(&self) -> Self {
        self.square()
    }

    /// Computes the square root of this element, if it exists.
    fn sqrt(&self) -> CtOption<Self> {
        // Tonelli-Shank's algorithm for q mod 16 = 1
        // https://eprint.iacr.org/2012/685.pdf (page 12, algorithm 5)
        match self.legendre() {
            LegendreSymbol::Zero => CtOption::new(*self, Choice::from(1u8)),
            LegendreSymbol::QuadraticNonResidue => CtOption::new(Fr::from(0), Choice::from(0u8)),
            LegendreSymbol::QuadraticResidue => {
                let mut c = ROOT_OF_UNITY;
                // r = self^((t + 1) // 2)
                let mut r = self.pow(&[
                    0x7fff2dff80000000,
                    0x4d0ec02a9ded201,
                    0x94cebea4199cec04,
                    0x39f6d3a9,
                ]);
                // t = self^t
                let mut t = self.pow(&[
                    0xfffe5bfeffffffff,
                    0x9a1d80553bda402,
                    0x299d7d483339d808,
                    0x73eda753,
                ]);
                let mut m = S;

                while t != Self::one() {
                    let mut i = 1;
                    {
                        let mut t2i = t;
                        t2i = t2i.square();
                        loop {
                            if t2i == Self::one() {
                                break;
                            }
                            t2i = t2i.square();
                            i += 1;
                        }
                    }

                    for _ in 0..(m - i - 1) {
                        c = c.square();
                    }
                    r = r.mul(&c);
                    c = c.square();
                    t = t.mul(&c);
                    m = i;
                }

                CtOption::new(r, Choice::from(1u8))
            }
        }
    }

    /// Computes the multiplicative inverse of this element,
    /// failing if the element is zero.
    fn invert(&self) -> CtOption<Self> {
        #[inline(always)]
        fn square_assign_multi(n: &mut Fr, num_times: usize) {
            for _ in 0..num_times {
                *n = n.square();
            }
        }
        // found using https://github.com/kwantam/addchain
        let mut t0 = self.square();
        let mut t1 = t0 * self;
        let mut t16 = t0.square();
        let mut t6 = t16.square();
        let mut t5 = t6 * t0;
        t0 = t6 * t16;
        let mut t12 = t5 * t16;
        let mut t2 = t6.square();
        let mut t7 = t5 * t6;
        let mut t15 = t0 * t5;
        let mut t17 = t12.square();
        t1 *= t17;
        let mut t3 = t7 * t2;
        let t8 = t1 * t17;
        let t4 = t8 * t2;
        let t9 = t8 * t7;
        t7 = t4 * t5;
        let t11 = t4 * t17;
        t5 = t9 * t17;
        let t14 = t7 * t15;
        let t13 = t11 * t12;
        t12 = t11 * t17;
        t15 *= &t12;
        t16 *= &t15;
        t3 *= &t16;
        t17 *= &t3;
        t0 *= &t17;
        t6 *= &t0;
        t2 *= &t6;
        square_assign_multi(&mut t0, 8);
        t0 *= &t17;
        square_assign_multi(&mut t0, 9);
        t0 *= &t16;
        square_assign_multi(&mut t0, 9);
        t0 *= &t15;
        square_assign_multi(&mut t0, 9);
        t0 *= &t15;
        square_assign_multi(&mut t0, 7);
        t0 *= &t14;
        square_assign_multi(&mut t0, 7);
        t0 *= &t13;
        square_assign_multi(&mut t0, 10);
        t0 *= &t12;
        square_assign_multi(&mut t0, 9);
        t0 *= &t11;
        square_assign_multi(&mut t0, 8);
        t0 *= &t8;
        square_assign_multi(&mut t0, 8);
        t0 *= self;
        square_assign_multi(&mut t0, 14);
        t0 *= &t9;
        square_assign_multi(&mut t0, 10);
        t0 *= &t8;
        square_assign_multi(&mut t0, 15);
        t0 *= &t7;
        square_assign_multi(&mut t0, 10);
        t0 *= &t6;
        square_assign_multi(&mut t0, 8);
        t0 *= &t5;
        square_assign_multi(&mut t0, 16);
        t0 *= &t3;
        square_assign_multi(&mut t0, 8);
        t0 *= &t2;
        square_assign_multi(&mut t0, 7);
        t0 *= &t4;
        square_assign_multi(&mut t0, 9);
        t0 *= &t2;
        square_assign_multi(&mut t0, 8);
        t0 *= &t3;
        square_assign_multi(&mut t0, 8);
        t0 *= &t2;
        square_assign_multi(&mut t0, 8);
        t0 *= &t2;
        square_assign_multi(&mut t0, 8);
        t0 *= &t2;
        square_assign_multi(&mut t0, 8);
        t0 *= &t3;
        square_assign_multi(&mut t0, 8);
        t0 *= &t2;
        square_assign_multi(&mut t0, 8);
        t0 *= &t2;
        square_assign_multi(&mut t0, 5);
        t0 *= &t1;
        square_assign_multi(&mut t0, 5);
        t0 *= &t1;

        CtOption::new(t0, !self.ct_eq(&Self::zero()))
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        // General implementation:
        //
        // a = num * inv0(div)
        //   = {    0    if div is zero
        //     { num/div otherwise
        //
        // b = G_S * a
        //   = {      0      if div is zero
        //     { G_S*num/div otherwise
        //
        // Since G_S is non-square, a and b are either both zero (and both square), or
        // only one of them is square. We can therefore choose the square root to return
        // based on whether a is square, but for the boolean output we need to handle the
        // num != 0 && div == 0 case specifically.

        let a = div.invert().unwrap_or_else(Self::zero) * num;
        let b = a * Self::ROOT_OF_UNITY;
        let sqrt_a = a.sqrt();
        let sqrt_b = b.sqrt();

        let num_is_zero = num.is_zero();
        let div_is_zero = div.is_zero();
        let is_square = sqrt_a.is_some();
        let is_nonsquare = sqrt_b.is_some();
        assert!(bool::from(
            num_is_zero | div_is_zero | (is_square ^ is_nonsquare)
        ));

        (
            is_square & !(!num_is_zero & div_is_zero),
            CtOption::conditional_select(&sqrt_b, &sqrt_a, is_square).unwrap(),
        )
    }
}

impl ff::PrimeField for Fr {
    type Repr = [u8; 32];

    const NUM_BITS: u32 = MODULUS_BITS;
    const CAPACITY: u32 = Self::NUM_BITS - 1;
    const MODULUS: &'static str = MODULUS_STR;
    const MULTIPLICATIVE_GENERATOR: Self = GENERATOR;
    const ROOT_OF_UNITY: Self = ROOT_OF_UNITY;
    const ROOT_OF_UNITY_INV: Self = ROOT_OF_UNITY_INV;
    const TWO_INV: Self = TWO_INV;
    const DELTA: Self = DELTA;
    const S: u32 = S;

    /// Attempts to convert a little-endian byte representation of
    /// a scalar into a `Scalar`, failing if the input is not canonical.
    fn from_repr(repr: Self::Repr) -> CtOption<Self> {
        let mut tmp = Fr([0, 0, 0, 0]);

        tmp.0[0] = u64::from_le_bytes(repr[0..8].try_into().unwrap());
        tmp.0[1] = u64::from_le_bytes(repr[8..16].try_into().unwrap());
        tmp.0[2] = u64::from_le_bytes(repr[16..24].try_into().unwrap());
        tmp.0[3] = u64::from_le_bytes(repr[24..32].try_into().unwrap());

        // Try to subtract the modulus
        let (_, borrow) = tmp.0[0].overflowing_sub(MODULUS.0[0]);
        let (_, borrow) = sbb(tmp.0[1], MODULUS.0[1], borrow as u64);
        let (_, borrow) = sbb(tmp.0[2], MODULUS.0[2], borrow);
        let (_, borrow) = sbb(tmp.0[3], MODULUS.0[3], borrow);

        // If the element is smaller than MODULUS then the
        // subtraction will underflow, producing a borrow value
        // of 0xffff...ffff. Otherwise, it'll be zero.
        let is_some = (borrow as u8) & 1;

        // Convert to Montgomery form by computing
        // (a.R^0 * R^2) / R = a.R
        tmp *= &R2;

        CtOption::new(tmp, Choice::from(is_some))
    }

    fn to_repr(&self) -> Self::Repr {
        // Turn into canonical form by computing
        // (a.R) / R = a
        #[cfg(feature = "asm")]
        let tmp = Fr::montgomery_reduce(&[self.0[0], self.0[1], self.0[2], self.0[3], 0, 0, 0, 0]);

        #[cfg(not(feature = "asm"))]
        let tmp = Fr::montgomery_reduce_short(&[self.0[0], self.0[1], self.0[2], self.0[3]]);

        let mut res = [0; 32];
        res[0..8].copy_from_slice(&tmp.0[0].to_le_bytes());
        res[8..16].copy_from_slice(&tmp.0[1].to_le_bytes());
        res[16..24].copy_from_slice(&tmp.0[2].to_le_bytes());
        res[24..32].copy_from_slice(&tmp.0[3].to_le_bytes());

        res
    }

    fn is_odd(&self) -> Choice {
        Choice::from(self.to_repr()[0] & 1)
    }
}

impl WithSmallOrderMulGroup<3> for Fr {
    const ZETA: Self = ZETA;
}

#[cfg(test)]
mod test {
    use super::*;
    use ff::Field;
    use rand_core::OsRng;

    #[test]
    fn test_ser() {
        let a0 = Fr::random(OsRng);
        let a_bytes = a0.to_bytes();
        let a1 = Fr::from_bytes(&a_bytes).unwrap();
        assert_eq!(a0, a1);
    }

    #[test]
    fn test_sqrt() {
        {
            assert_eq!(Fr::zero().sqrt().unwrap(), Fr::zero());
        }
        {
            assert_eq!(Fr::one().sqrt().unwrap(), Fr::one());
        }

        for _ in 0..100 {
            let a = Fr::random(OsRng);
            let mut b = a;
            b = b.square();
            let b = b.sqrt().unwrap();
            let mut negb = b;
            negb = negb.neg();
            assert!(a == b || a == negb);
        }
    }

    #[test]
    fn test_root_of_unity() {
        assert_eq!(
            Fr::ROOT_OF_UNITY.pow_vartime([1u64 << Fr::S, 0, 0, 0]),
            Fr::one()
        );
    }

    #[test]
    fn test_inv_root_of_unity() {
        assert_eq!(Fr::ROOT_OF_UNITY * Fr::ROOT_OF_UNITY_INV, Fr::one(),);
    }

    #[test]
    fn test_field() {
        crate::tests::field::random_field_tests::<Fr>("bls12-381 scalar".to_string());
    }

    #[test]
    fn test_delta() {
        assert_eq!(
            Fr::DELTA.pow(&[
                0xfffe_5bfe_ffff_ffff,
                0x09a1_d805_53bd_a402,
                0x299d_7d48_3339_d808,
                0x0000_0000_73ed_a753,
            ]),
            Fr::one(),
        );
    }

    #[test]
    fn test_from_u512_zero() {
        assert_eq!(
            Fr::zero(),
            Fr::from_u512([
                MODULUS.0[0],
                MODULUS.0[1],
                MODULUS.0[2],
                MODULUS.0[3],
                0,
                0,
                0,
                0
            ])
        );
    }

    #[test]
    fn test_from_u512_r() {
        assert_eq!(R, Fr::from_u512([1, 0, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn test_from_u512_r2() {
        assert_eq!(R2, Fr::from_u512([0, 0, 0, 0, 1, 0, 0, 0]));
    }

    #[test]
    fn test_from_u512_max() {
        let max_u64 = 0xffff_ffff_ffff_ffff;
        assert_eq!(
            R3 - R,
            Fr::from_u512([max_u64, max_u64, max_u64, max_u64, max_u64, max_u64, max_u64, max_u64])
        );
    }

    #[test]
    fn test_serialization() {
        crate::tests::field::random_serialization_test::<Fr>("fr".to_string());
    }
}
