//! This module implements message expansion consistent with the
//! hash-to-curve RFC drafts 7 through 10
//!
//! Source: https://github.com/privacy-scaling-explorations/bls12_381

use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};

use digest::{crypto_common::BlockSizeUser, Digest, ExtendableOutput, Update, XofReader};

use crate::bls12_381::generic_array::{
    typenum::{Unsigned, U32},
    ArrayLength, GenericArray,
};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

const OVERSIZE_DST_SALT: &[u8] = b"H2C-OVERSIZE-DST-";

/// The domain separation tag for a message expansion.
///
/// Implements [section 5.4.3 of `draft-irtf-cfrg-hash-to-curve-12`][dst].
///
/// [dst]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-12#section-5.4.3
#[derive(Debug)]
enum ExpandMsgDst<'x, L: ArrayLength<u8>> {
    /// DST produced by hashing a very long (> 255 chars) input DST.
    Hashed(GenericArray<u8, L>),
    /// A raw input DST (<= 255 chars).
    Raw(&'x [u8]),
}

impl<'x, L: ArrayLength<u8>> ExpandMsgDst<'x, L> {
    /// Produces a DST for use with `expand_message_xof`.
    pub fn process_xof<H>(dst: &'x [u8]) -> Self
    where
        H: Default + Update + ExtendableOutput,
    {
        if dst.len() > 255 {
            let mut data = GenericArray::<u8, L>::default();
            H::default()
                .chain(OVERSIZE_DST_SALT)
                .chain(dst)
                .finalize_xof()
                .read(&mut data);
            Self::Hashed(data)
        } else {
            Self::Raw(dst)
        }
    }

    /// Produces a DST for use with `expand_message_xmd`.
    pub fn process_xmd<H>(dst: &'x [u8]) -> Self
    where
        H: Digest<OutputSize = L>,
    {
        if dst.len() > 255 {
            Self::Hashed(
                H::new()
                    .chain_update(OVERSIZE_DST_SALT)
                    .chain_update(dst)
                    .finalize(),
            )
        } else {
            Self::Raw(dst)
        }
    }

    /// Returns the raw bytes of the DST.
    pub fn data(&'x self) -> &'x [u8] {
        match self {
            Self::Hashed(arr) => &arr[..],
            Self::Raw(buf) => buf,
        }
    }

    /// Returns the length of the DST.
    pub fn len(&'x self) -> usize {
        match self {
            Self::Hashed(_) => L::to_usize(),
            Self::Raw(buf) => buf.len(),
        }
    }
}

/// A trait for message expansion methods supported by hash-to-curve.
pub trait ExpandMessage: for<'x> InitExpandMessage<'x> {
    // This intermediate is likely only necessary until GATs allow
    // associated types with lifetimes.
}

/// Trait for constructing a new message expander.
pub trait InitExpandMessage<'x> {
    /// The state object used during message expansion.
    type Expander: ExpandMessageState<'x>;

    /// Initializes a message expander.
    fn init_expand(message: &[u8], dst: &'x [u8], len_in_bytes: usize) -> Self::Expander;
}

// Automatically derive trait
impl<X: for<'x> InitExpandMessage<'x>> ExpandMessage for X {}

/// Trait for types implementing the `expand_message` interface for `hash_to_field`.
pub trait ExpandMessageState<'x> {
    /// Reads bytes from the generated output.
    fn read_into(&mut self, output: &mut [u8]) -> usize;

    /// Retrieves the number of bytes remaining in the generator.
    fn remain(&self) -> usize;

    #[cfg(feature = "alloc")]
    /// Constructs a `Vec` containing the remaining bytes of the output.
    fn into_vec(mut self) -> Vec<u8>
    where
        Self: Sized,
    {
        let mut result = alloc::vec![0u8; self.remain()];
        self.read_into(&mut result[..]);
        result
    }
}

/// A generator for the output of `expand_message_xof` for a given
/// extendable hash function, message, DST, and output length.
///
/// Implements [section 5.4.2 of `draft-irtf-cfrg-hash-to-curve-12`][expand_message_xof]
/// with `k = 128`.
///
/// [expand_message_xof]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-12#section-5.4.2
pub struct ExpandMsgXof<H: ExtendableOutput> {
    hash: <H as ExtendableOutput>::Reader,
    remain: usize,
}

impl<H: ExtendableOutput> Debug for ExpandMsgXof<H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExpandMsgXof")
            .field("remain", &self.remain)
            .finish()
    }
}

impl<'x, H> ExpandMessageState<'x> for ExpandMsgXof<H>
where
    H: ExtendableOutput,
{
    fn read_into(&mut self, output: &mut [u8]) -> usize {
        let len = self.remain.min(output.len());
        self.hash.read(&mut output[..len]);
        self.remain -= len;
        len
    }

    fn remain(&self) -> usize {
        self.remain
    }
}

impl<'x, H> InitExpandMessage<'x> for ExpandMsgXof<H>
where
    H: Default + Update + ExtendableOutput,
{
    type Expander = Self;

    fn init_expand(message: &[u8], dst: &[u8], len_in_bytes: usize) -> Self {
        // Use U32 here for k = 128.
        let dst = ExpandMsgDst::<U32>::process_xof::<H>(dst);
        let hash = H::default()
            .chain(message)
            .chain((len_in_bytes as u16).to_be_bytes())
            .chain(dst.data())
            .chain([dst.len() as u8])
            .finalize_xof();
        Self {
            hash,
            remain: len_in_bytes,
        }
    }
}

/// Constructor for `expand_message_xmd` for a given digest hash function, message, DST,
/// and output length.
///
/// Implements [section 5.4.1 of `draft-irtf-cfrg-hash-to-curve-12`][expand_message_xmd].
///
/// [expand_message_xmd]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-12#section-5.4.1
#[derive(Debug)]
pub struct ExpandMsgXmd<H: Digest>(PhantomData<H>);

/// A generator for the output of `expand_message_xmd` for a given
/// digest hash function, message, DST, and output length.
///
/// Implements [section 5.4.1 of `draft-irtf-cfrg-hash-to-curve-12`][expand_message_xmd].
///
/// [expand_message_xmd]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-12#section-5.4.1
pub struct ExpandMsgXmdState<'x, H: Digest> {
    dst: ExpandMsgDst<'x, H::OutputSize>,
    b_0: GenericArray<u8, H::OutputSize>,
    b_i: GenericArray<u8, H::OutputSize>,
    i: usize,
    b_offs: usize,
    remain: usize,
}

impl<H: Digest> Debug for ExpandMsgXmdState<'_, H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExpandMsgXmdState")
            .field("remain", &self.remain)
            .finish()
    }
}

impl<'x, H> InitExpandMessage<'x> for ExpandMsgXmd<H>
where
    H: Digest + BlockSizeUser,
{
    type Expander = ExpandMsgXmdState<'x, H>;

    fn init_expand(message: &[u8], dst: &'x [u8], len_in_bytes: usize) -> Self::Expander {
        let hash_size = <H as Digest>::output_size();
        let ell = (len_in_bytes + hash_size - 1) / hash_size;
        if ell > 255 {
            panic!("Invalid ExpandMsgXmd usage: ell > 255");
        }
        let dst = ExpandMsgDst::process_xmd::<H>(dst);
        let b_0 = H::new()
            .chain_update(GenericArray::<u8, <H>::BlockSize>::default())
            .chain_update(message)
            .chain_update((len_in_bytes as u16).to_be_bytes())
            .chain_update([0u8])
            .chain_update(dst.data())
            .chain_update([dst.len() as u8])
            .finalize();
        // init with b_1
        let b_i = H::new()
            .chain_update(&b_0)
            .chain_update([1u8])
            .chain_update(dst.data())
            .chain_update([dst.len() as u8])
            .finalize();
        ExpandMsgXmdState {
            dst,
            b_0,
            b_i,
            i: 2,
            b_offs: 0,
            remain: len_in_bytes,
        }
    }
}

impl<'x, H> ExpandMessageState<'x> for ExpandMsgXmdState<'x, H>
where
    H: Digest,
{
    fn read_into(&mut self, output: &mut [u8]) -> usize {
        let read_len = self.remain.min(output.len());
        let mut offs = 0;
        let hash_size = H::OutputSize::to_usize();
        while offs < read_len {
            let b_offs = self.b_offs;
            let mut copy_len = hash_size - b_offs;
            if copy_len > 0 {
                copy_len = copy_len.min(read_len - offs);
                output[offs..(offs + copy_len)]
                    .copy_from_slice(&self.b_i[b_offs..(b_offs + copy_len)]);
                offs += copy_len;
                self.b_offs = b_offs + copy_len;
            } else {
                let mut b_prev_xor = self.b_0.clone();
                for j in 0..hash_size {
                    b_prev_xor[j] ^= self.b_i[j];
                }
                self.b_i = H::new()
                    .chain_update(b_prev_xor)
                    .chain_update([self.i as u8])
                    .chain_update(self.dst.data())
                    .chain_update([self.dst.len() as u8])
                    .finalize();
                self.b_offs = 0;
                self.i += 1;
            }
        }
        self.remain -= read_len;
        read_len
    }

    fn remain(&self) -> usize {
        self.remain
    }
}

#[cfg(feature = "alloc")]
#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Sha256, Sha512};

    /// From <https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-12#appendix-K.1>
    #[test]
    fn expand_message_xmd_works_for_draft12_testvectors_sha256() {
        let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";

        let msg = b"";
        let len_in_bytes = 0x20;
        let uniform_bytes = hex::decode(
            "68a985b87eb6b46952128911f2a4412bbc302a9d759667f8\
            7f7a21d803f07235",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abc";
        let len_in_bytes = 0x20;
        let uniform_bytes = hex::decode(
            "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b979\
            02f53a8a0d605615",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abcdef0123456789";
        let len_in_bytes = 0x20;
        let uniform_bytes = hex::decode(
            "eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2c\
            b4eafe524333f5c1",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
            qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
            qqqqqqqqqqqqqqqqqqqqqqqqq";
        let len_in_bytes = 0x20;
        let uniform_bytes = hex::decode(
            "b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa5\
            1bfe3f12ddad1ff9",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let len_in_bytes = 0x20;
        let uniform_bytes = hex::decode(
            "4623227bcc01293b8c130bf771da8c298dede7383243dc09\
            93d2d94823958c4c",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"";
        let len_in_bytes = 0x80;
        let uniform_bytes = hex::decode(
            "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac0\
            6d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4\
            cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec8\
            49469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472\
            c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abc";
        let len_in_bytes = 0x80;
        let uniform_bytes = hex::decode(
            "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2\
            fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b\
            664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221\
            b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425\
            cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abcdef0123456789";
        let len_in_bytes = 0x80;
        let uniform_bytes = hex::decode(
            "ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d6\
            29831a74c6572bd9ebd0df635cd1f208e2038e760c4994984ce73f\
            0d55ea9f22af83ba4734569d4bc95e18350f740c07eef653cbb9f8\
            7910d833751825f0ebefa1abe5420bb52be14cf489b37fe1a72f7d\
            e2d10be453b2c9d9eb20c7e3f6edc5a60629178d9478df",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
            qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
            qqqqqqqqqqqqqqqqqqqqqqqqq";
        let len_in_bytes = 0x80;
        let uniform_bytes = hex::decode(
            "80be107d0884f0d881bb460322f0443d38bd222db8bd0b0a\
            5312a6fedb49c1bbd88fd75d8b9a09486c60123dfa1d73c1cc3169\
            761b17476d3c6b7cbbd727acd0e2c942f4dd96ae3da5de368d26b3\
            2286e32de7e5a8cb2949f866a0b80c58116b29fa7fabb3ea7d520e\
            e603e0c25bcaf0b9a5e92ec6a1fe4e0391d1cdbce8c68a",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let len_in_bytes = 0x80;
        let uniform_bytes = hex::decode(
            "546aff5444b5b79aa6148bd81728704c32decb73a3ba76e9\
            e75885cad9def1d06d6792f8a7d12794e90efed817d96920d72889\
            6a4510864370c207f99bd4a608ea121700ef01ed879745ee3e4cee\
            f777eda6d9e5e38b90c86ea6fb0b36504ba4a45d22e86f6db5dd43\
            d98a294bebb9125d5b794e9d2a81181066eb954966a487",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );
    }

    /// From <https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-12#appendix-K.2>
    #[test]
    fn expand_message_xmd_works_for_draft12_testvectors_sha256_long_dst() {
        let dst = b"QUUX-V01-CS02-with-expander-SHA256-128-long-DST-111111\
            111111111111111111111111111111111111111111111111111111\
            111111111111111111111111111111111111111111111111111111\
            111111111111111111111111111111111111111111111111111111\
            1111111111111111111111111111111111111111";

        let msg = b"";
        let len_in_bytes = 0x20;
        let uniform_bytes = hex::decode(
            "e8dc0c8b686b7ef2074086fbdd2f30e3f8bfbd3bdf177f73\
            f04b97ce618a3ed3",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abc";
        let len_in_bytes = 0x20;
        let uniform_bytes = hex::decode(
            "52dbf4f36cf560fca57dedec2ad924ee9c266341d8f3d6af\
            e5171733b16bbb12",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abcdef0123456789";
        let len_in_bytes = 0x20;
        let uniform_bytes = hex::decode(
            "35387dcf22618f3728e6c686490f8b431f76550b0b2c61cb\
            c1ce7001536f4521",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
            qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
            qqqqqqqqqqqqqqqqqqqqqqqqq";
        let len_in_bytes = 0x20;
        let uniform_bytes = hex::decode(
            "01b637612bb18e840028be900a833a74414140dde0c4754c\
            198532c3a0ba42bc",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let len_in_bytes = 0x20;
        let uniform_bytes = hex::decode(
            "20cce7033cabc5460743180be6fa8aac5a103f56d481cf36\
            9a8accc0c374431b",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"";
        let len_in_bytes = 0x80;
        let uniform_bytes = hex::decode(
            "14604d85432c68b757e485c8894db3117992fc57e0e136f7\
            1ad987f789a0abc287c47876978e2388a02af86b1e8d1342e5ce4f\
            7aaa07a87321e691f6fba7e0072eecc1218aebb89fb14a0662322d\
            5edbd873f0eb35260145cd4e64f748c5dfe60567e126604bcab1a3\
            ee2dc0778102ae8a5cfd1429ebc0fa6bf1a53c36f55dfc",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abc";
        let len_in_bytes = 0x80;
        let uniform_bytes = hex::decode(
            "1a30a5e36fbdb87077552b9d18b9f0aee16e80181d5b951d\
            0471d55b66684914aef87dbb3626eaabf5ded8cd0686567e503853\
            e5c84c259ba0efc37f71c839da2129fe81afdaec7fbdc0ccd4c794\
            727a17c0d20ff0ea55e1389d6982d1241cb8d165762dbc39fb0cee\
            4474d2cbbd468a835ae5b2f20e4f959f56ab24cd6fe267",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abcdef0123456789";
        let len_in_bytes = 0x80;
        let uniform_bytes = hex::decode(
            "d2ecef3635d2397f34a9f86438d772db19ffe9924e28a1ca\
            f6f1c8f15603d4028f40891044e5c7e39ebb9b31339979ff33a424\
            9206f67d4a1e7c765410bcd249ad78d407e303675918f20f26ce6d\
            7027ed3774512ef5b00d816e51bfcc96c3539601fa48ef1c07e494\
            bdc37054ba96ecb9dbd666417e3de289d4f424f502a982",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
            qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
            qqqqqqqqqqqqqqqqqqqqqqqqq";
        let len_in_bytes = 0x80;
        let uniform_bytes = hex::decode(
            "ed6e8c036df90111410431431a232d41a32c86e296c05d42\
            6e5f44e75b9a50d335b2412bc6c91e0a6dc131de09c43110d9180d\
            0a70f0d6289cb4e43b05f7ee5e9b3f42a1fad0f31bac6a625b3b5c\
            50e3a83316783b649e5ecc9d3b1d9471cb5024b7ccf40d41d1751a\
            04ca0356548bc6e703fca02ab521b505e8e45600508d32",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let len_in_bytes = 0x80;
        let uniform_bytes = hex::decode(
            "78b53f2413f3c688f07732c10e5ced29a17c6a16f717179f\
            fbe38d92d6c9ec296502eb9889af83a1928cd162e845b0d3c5424e\
            83280fed3d10cffb2f8431f14e7a23f4c68819d40617589e4c4116\
            9d0b56e0e3535be1fd71fbb08bb70c5b5ffed953d6c14bf7618b35\
            fc1f4c4b30538236b4b08c9fbf90462447a8ada60be495",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha256>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );
    }

    /// From <https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-12#appendix-K.3>
    #[test]
    fn expand_message_xmd_works_for_draft12_testvectors_sha512() {
        let dst = b"QUUX-V01-CS02-with-expander-SHA512-256";

        let msg = b"";
        let len_in_bytes = 0x20;
        let uniform_bytes = hex::decode(
            "6b9a7312411d92f921c6f68ca0b6380730a1a4d982c50721\
            1a90964c394179ba",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha512>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abc";
        let len_in_bytes = 0x20;
        let uniform_bytes = hex::decode(
            "0da749f12fbe5483eb066a5f595055679b976e93abe9be6f\
            0f6318bce7aca8dc",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha512>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abcdef0123456789";
        let len_in_bytes = 0x20;
        let uniform_bytes = hex::decode(
            "087e45a86e2939ee8b91100af1583c4938e0f5fc6c9db4b1\
            07b83346bc967f58",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha512>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
            qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
            qqqqqqqqqqqqqqqqqqqqqqqqq";
        let len_in_bytes = 0x20;
        let uniform_bytes = hex::decode(
            "7336234ee9983902440f6bc35b348352013becd88938d2af\
            ec44311caf8356b3",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha512>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let len_in_bytes = 0x20;
        let uniform_bytes = hex::decode(
            "57b5f7e766d5be68a6bfe1768e3c2b7f1228b3e4b3134956\
            dd73a59b954c66f4",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha512>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"";
        let len_in_bytes = 0x80;
        let uniform_bytes = hex::decode(
            "41b037d1734a5f8df225dd8c7de38f851efdb45c372887be\
            655212d07251b921b052b62eaed99b46f72f2ef4cc96bfaf254ebb\
            bec091e1a3b9e4fb5e5b619d2e0c5414800a1d882b62bb5cd1778f\
            098b8eb6cb399d5d9d18f5d5842cf5d13d7eb00a7cff859b605da6\
            78b318bd0e65ebff70bec88c753b159a805d2c89c55961",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha512>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abc";
        let len_in_bytes = 0x80;
        let uniform_bytes = hex::decode(
            "7f1dddd13c08b543f2e2037b14cefb255b44c83cc397c178\
            6d975653e36a6b11bdd7732d8b38adb4a0edc26a0cef4bb4521713\
            5456e58fbca1703cd6032cb1347ee720b87972d63fbf232587043e\
            d2901bce7f22610c0419751c065922b488431851041310ad659e4b\
            23520e1772ab29dcdeb2002222a363f0c2b1c972b3efe1",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha512>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"abcdef0123456789";
        let len_in_bytes = 0x80;
        let uniform_bytes = hex::decode(
            "3f721f208e6199fe903545abc26c837ce59ac6fa45733f1b\
            aaf0222f8b7acb0424814fcb5eecf6c1d38f06e9d0a6ccfbf85ae6\
            12ab8735dfdf9ce84c372a77c8f9e1c1e952c3a61b7567dd069301\
            6af51d2745822663d0c2367e3f4f0bed827feecc2aaf98c949b5ed\
            0d35c3f1023d64ad1407924288d366ea159f46287e61ac",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha512>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
            qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
            qqqqqqqqqqqqqqqqqqqqqqqqq";
        let len_in_bytes = 0x80;
        let uniform_bytes = hex::decode(
            "b799b045a58c8d2b4334cf54b78260b45eec544f9f2fb5bd\
            12fb603eaee70db7317bf807c406e26373922b7b8920fa29142703\
            dd52bdf280084fb7ef69da78afdf80b3586395b433dc66cde048a2\
            58e476a561e9deba7060af40adf30c64249ca7ddea79806ee5beb9\
            a1422949471d267b21bc88e688e4014087a0b592b695ed",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha512>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );

        let msg = b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let len_in_bytes = 0x80;
        let uniform_bytes = hex::decode(
            "05b0bfef265dcee87654372777b7c44177e2ae4c13a27f10\
            3340d9cd11c86cb2426ffcad5bd964080c2aee97f03be1ca18e30a\
            1f14e27bc11ebbd650f305269cc9fb1db08bf90bfc79b42a952b46\
            daf810359e7bc36452684784a64952c343c52e5124cd1f71d474d5\
            197fefc571a92929c9084ffe1112cf5eea5192ebff330b",
        )
        .unwrap();
        assert_eq!(
            ExpandMsgXmd::<Sha512>::init_expand(msg, dst, len_in_bytes).into_vec(),
            uniform_bytes
        );
    }
}
