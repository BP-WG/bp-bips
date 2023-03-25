// Bitcoin hierarchical deterministic derivation library
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2020-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2020-2023 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2020-2023 Dr Maxim Orlovsky. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use amplify::{Array, RawArray, Wrapper};
use bitcoin_hashes::{ripemd160, sha512, Hash, Hmac, HmacEngine};
use secp256k1::{PublicKey, XOnlyPublicKey};

use crate::{
    Chaincode, ChildIdx, DerivationIndex, Fingerprint, NormIdx, TooDeepDerivation, XkeyDecodeError,
    XKEY_LEN,
};

/// Extended pubkey identifier - a hash of the extended pubkey data.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Index, RangeOps, BorrowSlice, Hex, Display, FromStr)]
pub struct XpubIdentifier(
    #[from]
    #[from([u8; 20])]
    Array<u8, 20>,
);

/// Extended public key.
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub struct Xpub([u8; XKEY_LEN]);

impl Xpub {
    pub const MAGIC_MAINNET: [u8; 4] = [0x04u8, 0x88, 0xB2, 0x1E];
    pub const MAGIC_TESTNET: [u8; 4] = [0x04u8, 0x35, 0x87, 0xCF];

    pub fn is_mainnet(&self) -> bool { !self.is_testnet() }

    pub fn is_testnet(&self) -> bool { &self.0[..4] == &Self::MAGIC_TESTNET }

    /// How many derivations this key is from the master (which is 0).
    pub fn depth(&self) -> u8 { self.0[4] }

    /// Fingerprint of the parent key; zero bytes if not known.
    pub fn parent_fingerprint(&self) -> Fingerprint {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&self.0[5..9]);
        Fingerprint::from_raw_array(buf)
    }

    /// Child number of the key used to derive from parent (0 for master).
    pub fn child_number(&self) -> ChildIdx {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&self.0[9..13]);
        let idx = u32::from_be_bytes(buf);
        ChildIdx::with_raw_value(idx)
    }

    /// Chain code.
    pub fn chain_code(&self) -> Chaincode {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&self.0[13..45]);
        Chaincode::from_raw_array(buf)
    }

    /// Public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_slice(&self.0[45..78]).expect("public key is checked on deserialization")
    }

    /// Constructs BIP340 x-only public key for BIP-340 signatures and Taproot use matching
    /// the internal public key representation.
    pub fn into_x_only_pk(self) -> XOnlyPublicKey { XOnlyPublicKey::from(self.public_key()) }

    /// Attempts to derive an extended public key from a path.
    pub fn derive(
        &self,
        path: impl IntoIterator<Item = impl Into<NormIdx>>,
    ) -> Result<Xpub, TooDeepDerivation> {
        let mut pk: Xpub = *self;
        for cnum in path {
            pk = pk.ckd_pub(cnum)?
        }
        Ok(pk)
    }

    /// Public->Public child key derivation.
    pub fn ckd_pub(&self, index: impl Into<NormIdx>) -> Result<Xpub, TooDeepDerivation> {
        use bitcoin_hashes::HashEngine;

        let child_number = index.into();
        if self.depth() == u8::MAX {
            return Err(TooDeepDerivation);
        }

        // chain code
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(&self.chain_code()[..]);
        // public key
        let pk = self.public_key();
        hmac_engine.input(&pk.serialize());
        hmac_engine.input(&child_number.first_raw_value().to_be_bytes());

        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

        let private_key =
            secp256k1::SecretKey::from_slice(&hmac_result[..32]).expect("negligible probability");

        let mut buf = [0u8; 32];
        buf.copy_from_slice(&hmac_result.to_byte_array()[32..]);
        let chain_code = Chaincode::from_raw_array(buf);

        let tweaked = pk
            .add_exp_tweak(secp256k1::SECP256K1, &private_key.into())
            .expect("negligible probability");

        let mut xpub = *self;
        xpub.0[4] = self.depth() + 1;
        xpub.0[5..9].copy_from_slice(&self.fingerprint().to_raw_array());
        xpub.0[9..13].copy_from_slice(&child_number.first_raw_value().to_be_bytes());
        xpub.0[13..45].copy_from_slice(&chain_code.to_raw_array());
        xpub.0[45..78].copy_from_slice(&tweaked.serialize());
        Ok(xpub)
    }

    /// Decoding extended public key from binary data according to BIP 32.
    pub fn decode_binary(binary: &[u8]) -> Result<Self, XkeyDecodeError> {
        if binary.len() != XKEY_LEN {
            return Err(XkeyDecodeError::InvalidLen(binary.len()));
        }
        let mut pk = [0u8; 33];
        pk.copy_from_slice(&binary[45..78]);
        PublicKey::from_slice(&pk).map_err(|_| XkeyDecodeError::InvalidKey(pk.into()))?;
        let mut data = [0u8; XKEY_LEN];
        data.copy_from_slice(binary);
        Ok(Self(data))
    }

    /// Extended public key binary encoding according to BIP 32.
    pub fn encode_binary(&self) -> [u8; 78] { self.0 }

    /// Returns the HASH160 of the chaincode.
    pub fn identifier(&self) -> XpubIdentifier {
        use std::io::Write;

        let mut engine = ripemd160::Hash::engine();
        engine.write_all(&self.public_key().serialize()).expect("engines don't error");
        let hash = ripemd160::Hash::from_engine(engine);
        XpubIdentifier::from_raw_array(hash.to_byte_array())
    }

    /// Returns fingerprint (the first four bytes of the xpub identifier).
    pub fn fingerprint(&self) -> Fingerprint {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&self.identifier().to_raw_array()[..4]);
        Fingerprint::from_raw_array(buf)
    }
}

mod display_from_str {
    use core::fmt::{self, Display, Formatter};
    use core::str::FromStr;

    use base58::{FromBase58, ToBase58};
    use bitcoin_hashes::sha256d;

    use super::*;
    use crate::XkeyParseError;

    impl Display for Xpub {
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            let mut data = self.encode_binary().to_vec();
            let hash = sha256d::Hash::hash(&data);
            data.extend(&hash[..4]);
            f.write_str(&data.to_base58())
        }
    }

    impl FromStr for Xpub {
        type Err = XkeyParseError;

        fn from_str(inp: &str) -> Result<Xpub, XkeyParseError> {
            let mut data = inp.from_base58()?;
            let len = data.len();
            if len != XKEY_LEN + 4 {
                return Err(XkeyParseError::InvalidLen(len));
            }
            let data_len = len - 4;

            let mut expected = [0u8; 4];
            expected.copy_from_slice(&data[data_len..]);
            let hash = sha256d::Hash::hash(&data[..data_len]);
            let mut actual = [0u8; 4];
            actual.copy_from_slice(&hash[..4]);
            if actual != expected {
                return Err(XkeyParseError::InvalidChecksum {
                    actual: actual.into(),
                    expected: expected.into(),
                });
            }

            data.truncate(data_len);
            Xpub::decode_binary(&data).map_err(XkeyParseError::from)
        }
    }
}
