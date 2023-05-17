//! This module implements the Nova traits for bn256::G1, bn256::Fr, grumpkin::G1, grumpkin::Fr.
use crate::{
  provider::{
    keccak::Keccak256Transcript,
    pedersen::CommitmentEngine,
    poseidon::{PoseidonRO, PoseidonROCircuit},
    msm::cpu_best_multiexp,
  },
  traits::{CompressedGroup, Group, PrimeFieldExt, TranscriptReprTrait},
};

use halo2curves::{
  CurveAffineExt, CurveExt,
  bn256,
  grumpkin,
  group::{Curve, GroupEncoding, Group as bnGroup},
};

use rayon::prelude::*;
use ff::{FromUniformBytes, PrimeField};
use num_bigint::BigInt;
use num_traits::Num;
use serde::{Deserialize, Serialize};
use sha3::Shake256;


/// A wrapper for compressed group elements of bn256
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Bn256CompressedElementWrapper {
    repr: [u8; 32],
}

impl Bn256CompressedElementWrapper {
  /// Wraps repr into the wrapper
  pub fn new(repr: [u8; 32]) -> Self {
    Self { repr }
  }
}

/// A wrapper for compressed group elements of grumpkin
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GrumpkinCompressedElementWrapper {
    repr: [u8; 32],
}

impl GrumpkinCompressedElementWrapper {
  /// Wraps repr into the wrapper
  pub fn new(repr: [u8; 32]) -> Self {
    Self { repr }
  }
}

macro_rules! impl_traits {
  (
    $name:ident,
    $name_compressed:ident,
    $name_curve:ident,
    $name_curve_affine:ident,
    $order_str:literal
  ) => {
    impl Group for $name::G1 {
      type Base = $name::Fq;
      type Scalar = $name::Fr;
      type CompressedGroupElement = $name_compressed;
      type PreprocessedGroupElement = $name::G1Affine;
      type RO = PoseidonRO<Self::Base, Self::Scalar>;
      type ROCircuit = PoseidonROCircuit<Self::Base>;
      type TE = Keccak256Transcript<Self>;
      type CE = CommitmentEngine<Self>;

      #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
      fn vartime_multiscalar_mul(
        scalars: &[Self::Scalar],
        bases: &[Self::PreprocessedGroupElement],
      ) -> Self {
          cpu_best_multiexp(scalars, bases)
      }

      fn preprocessed(&self) -> Self::PreprocessedGroupElement {
        self.to_affine()
      }

      fn compress(&self) -> Self::CompressedGroupElement {
          unimplemented!()
      }

      fn from_label(label: &'static [u8], n: usize) -> Vec<Self::PreprocessedGroupElement> {
          unimplemented!();
      }

      fn to_coordinates(&self) -> (Self::Base, Self::Base, bool) {
          let (x, y) = self.to_affine().into_coordinates();
          (x, y, bool::from(self.is_identity()))
      }

      fn get_curve_params() -> (Self::Base, Self::Base, BigInt) {
          let a = $name::G1::a();
          let b = $name::G1::b();
          let order = BigInt::from_str_radix($order_str, 16).unwrap();
          (a, b, order)
      }

      fn zero() -> Self {
          $name::G1::identity()
      }

      fn get_generator() -> Self {
          $name::G1::generator()
      }
    }

    impl PrimeFieldExt for $name::Fr {
      fn from_uniform(bytes: &[u8]) -> Self {
        let bytes_arr: [u8; 64] = bytes.try_into().unwrap();
        $name::Fr::from_uniform_bytes(&bytes_arr)
      }
    }

    impl<G: Group> TranscriptReprTrait<G> for $name_compressed {
      fn to_transcript_bytes(&self) -> Vec<u8> {
        self.repr.to_vec()
      }
    }

    impl CompressedGroup for $name_compressed {
      type GroupElement = $name::G1;

      fn decompress(&self) -> Option<$name::G1> {
          Some($name::G1::from_bytes(&$name::G1Compressed::from_slice(&self.repr).unwrap()).unwrap())
      }
    }

  };
}


impl<G: Group> TranscriptReprTrait<G> for bn256::Fq {
  fn to_transcript_bytes(&self) -> Vec<u8> {
    self.to_repr().to_vec()
  }
}

impl<G: Group> TranscriptReprTrait<G> for bn256::Fr {
  fn to_transcript_bytes(&self) -> Vec<u8> {
    self.to_repr().to_vec()
  }
}

impl_traits!(
  bn256,
  Bn256CompressedElementWrapper,
  G1,
  G1Affine,
  "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"
);


/*
impl_traits!(
  grumpkin,
  GrumpkinCompressedElementWrapper,
  G1,
  G1Affine,
  "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47"
);
*/


