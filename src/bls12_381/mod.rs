//! # `bls12_381`
//!
//! This crate provides an implementation of the BLS12-381 pairing-friendly elliptic
//! curve construction.
//!
//! * **This implementation has not been reviewed or audited. Use at your own risk.**
//! * This implementation targets Rust `1.36` or later.
//! * This implementation does not require the Rust standard library.
//! * All operations are constant time unless explicitly noted.

// Catch documentation errors caused by code changes.
#![allow(clippy::too_many_arguments)]
#![allow(clippy::many_single_char_names)]
// This lint is described at
// https://rust-lang.github.io/rust-clippy/master/index.html#suspicious_arithmetic_impl
// In our library, some of the arithmetic involving extension fields will necessarily
// involve various binary operators, and so this lint is triggered unnecessarily.
#![allow(clippy::suspicious_arithmetic_impl)]

#[macro_use]
mod util;

mod scalar;

pub use fp::Fp as Fq;
pub use scalar::Scalar as Fr;

use scalar::Scalar;

mod fp;
mod fp2;
mod g1;
mod g2;

use g1::G1Projective;
use g2::G2Projective;

pub use g1::{G1Affine, G1Projective as G1};
pub use g2::{G2Affine, G2Projective as G2};

mod fp12;
mod fp6;

pub use fp12::{Fp12 as Fq12, FROBENIUS_COEFF_FQ12_C1};
pub use fp2::Fp2 as Fq2;
pub use fp6::Fp6 as Fq6;

// The BLS parameter x for BLS12-381 is -0xd201000000010000
pub const BLS_X: u64 = 0xd201_0000_0001_0000;
pub const BLS_X_IS_NEGATIVE: bool = true;

mod pairings;

pub use pairings::{pairing, Bls12, Gt, MillerLoopResult};

pub use pairings::{multi_miller_loop, G2Prepared};

// use crate::arithmetic::mul_512;
// use crate::arithmetic::sbb;
// use crate::{
//     arithmetic::{CurveEndo, EndoParameters},
//     endo,
// };
// use ff::PrimeField;
// use ff::WithSmallOrderMulGroup;
// use std::convert::TryInto;

// // Obtained from https://github.com/ConsenSys/gnark-crypto/blob/master/ecc/utils.go
// // See https://github.com/demining/Endomorphism-Secp256k1/blob/main/README.md
// // to have more details about the endomorphism.
// const ENDO_PARAMS_BLS: EndoParameters = EndoParameters {
//     // round(b2/n)
//     gamma2: [0x63f6e522f6cfee30u64, 0x7c6becf1e01faadd, 0x01, 0x0],
//     // round(-b1/n)
//     gamma1: [0x02u64, 0x0, 0x0, 0x0],
//     b1: [0x01u64, 0x0, 0x0, 0x0],
//     b2: [0x0000000100000000, 0xac45a4010001a402, 0x0, 0x0],
// };

// endo!(G1Projective, Scalar, ENDO_PARAMS_BLS);

// #[test]
// fn test_endo() {
//     use ff::Field;
//     use rand_core::OsRng;

//     for _ in 0..100000 {
//         let k = Scalar::random(OsRng);
//         let (k1, k1_neg, k2, k2_neg) = G1Projective::decompose_scalar(&k);
//         if k1_neg & k2_neg {
//             assert_eq!(
//                 k,
//                 -Scalar::from_u128(k1) + Scalar::ZETA * Scalar::from_u128(k2)
//             )
//         } else if k1_neg {
//             assert_eq!(
//                 k,
//                 -Scalar::from_u128(k1) - Scalar::ZETA * Scalar::from_u128(k2)
//             )
//         } else if k2_neg {
//             assert_eq!(
//                 k,
//                 Scalar::from_u128(k1) + Scalar::ZETA * Scalar::from_u128(k2)
//             )
//         } else {
//             assert_eq!(
//                 k,
//                 Scalar::from_u128(k1) - Scalar::ZETA * Scalar::from_u128(k2)
//             )
//         }
//     }

//     for _ in 0..100000 {
//         let k = Scalar::random(OsRng);
//         let (k1, k1_neg, k2, k2_neg) = G1Projective::decompose_scalar(&k);
//         if k1_neg & k2_neg {
//             assert_eq!(
//                 k,
//                 -Scalar::from_u128(k1) + Scalar::ZETA * Scalar::from_u128(k2)
//             )
//         } else if k1_neg {
//             assert_eq!(
//                 k,
//                 -Scalar::from_u128(k1) - Scalar::ZETA * Scalar::from_u128(k2)
//             )
//         } else if k2_neg {
//             assert_eq!(
//                 k,
//                 Scalar::from_u128(k1) + Scalar::ZETA * Scalar::from_u128(k2)
//             )
//         } else {
//             assert_eq!(
//                 k,
//                 Scalar::from_u128(k1) - Scalar::ZETA * Scalar::from_u128(k2)
//             )
//         }
//     }
// }
