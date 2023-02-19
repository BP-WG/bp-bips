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

use amplify::{Array, Bytes32};
use bitcoin_hashes::{ripemd160, sha512, Hash, Hmac, HmacEngine};
use secp256k1::{PublicKey, XOnlyPublicKey};

use crate::{ChildIdx, DerivationIndex, NormIdx};

/// Chaincode used for extended key hierarchical derivation.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Index, RangeOps, BorrowSlice, Hex, Display, FromStr)]
pub struct Chaincode(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

/// Extended public key fingerprint.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default, From)]
pub struct Fingerprint(
    #[from]
    #[from([u8; 4])]
    Array<u8, 4>,
);

/// Extended pubkey identifier - a hash of the extended pubkey data.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Index, RangeOps, BorrowSlice, Hex, Display, FromStr)]
pub struct XpubIdentifier(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

/// Extended public key.
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub struct Xpub {
    /// The network this key is to be used on.
    pub testnet: bool,
    /// How many derivations this key is from the master (which is 0).
    pub depth: u8,
    /// Fingerprint of the parent key; zero bytes if not known.
    pub parent_fingerprint: Fingerprint,
    /// Child number of the key used to derive from parent (0 for master).
    pub child_number: ChildIdx,
    /// Public key.
    pub public_key: PublicKey,
    /// Chain code.
    pub chain_code: Chaincode,
}

impl Xpub {
    /// Constructs BIP340 x-only public key for BIP-340 signatures and Taproot use matching
    /// the internal public key representation.
    pub fn into_x_only_pk(self) -> XOnlyPublicKey { XOnlyPublicKey::from(self.public_key) }

    /// Attempts to derive an extended public key from a path.
    pub fn derive<P: AsRef<[C]>, C: Into<NormIdx>>(&self, path: P) -> Result<Xpub, Error> {
        let mut pk: Xpub = *self;
        for cnum in path.as_ref() {
            pk = pk.ckd_pub(secp, cnum)?
        }
        Ok(pk)
    }

    /// Public->Public child key derivation
    pub fn ckd_pub<C: secp256k1::Verification>(
        &self,
        index: impl Into<NormIdx>,
    ) -> Result<Xpub, Error> {
        use bitcoin_hashes::HashEngine;

        let child_number = index.into();

        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(&self.chain_code[..]);
        hmac_engine.input(&self.public_key.serialize()[..]);
        hmac_engine.input(&child_number.first_raw_value().to_be_bytes());

        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

        let private_key = secp256k1::SecretKey::from_slice(&hmac_result[..32])?;
        let chain_code = Chaincode(hmac_result.into_inner().into());

        let tweaked = self.public_key.add_exp_tweak(secp, &private_key.into())?;

        Ok(Xpub {
            testnet: self.testnet,
            depth: self.depth.checked_add(1).ok_or()?,
            parent_fingerprint: self.fingerprint(),
            child_number: child_number.into(),
            public_key: tweaked,
            chain_code,
        })
    }

    /// Decoding extended public key from binary data according to BIP 32
    pub fn decode(data: &[u8]) -> Result<Xpub, Error> {
        if data.len() != 78 {
            return Err(Error::WrongExtendedKeyLength(data.len()));
        }

        Ok(Xpub {
            network: if data[0..4] == [0x04u8, 0x88, 0xB2, 0x1E] {
                Network::Bitcoin
            } else if data[0..4] == [0x04u8, 0x35, 0x87, 0xCF] {
                Network::Testnet
            } else {
                let mut ver = [0u8; 4];
                ver.copy_from_slice(&data[0..4]);
                return Err(Error::UnknownVersion(ver));
            },
            depth: data[4],
            parent_fingerprint: data[5..9]
                .try_into()
                .expect("9 - 5 == 4, which is the Fingerprint length"),
            child_number: ChildIdx::with_raw_value(),
            chain_code: data[13..45]
                .try_into()
                .expect("45 - 13 == 32, which is the ChainCode length"),
            public_key: PublicKey::from_slice(&data[45..78])?,
        })
    }

    /// Extended public key binary encoding according to BIP 32
    pub fn encode(&self) -> [u8; 78] {
        let mut ret = [0; 78];
        ret[0..4].copy_from_slice(
            &match self.network {
                Network::Bitcoin => [0x04u8, 0x88, 0xB2, 0x1E],
                Network::Testnet | Network::Signet | Network::Regtest => [0x04u8, 0x35, 0x87, 0xCF],
            }[..],
        );
        ret[4] = self.depth;
        ret[5..9].copy_from_slice(&self.parent_fingerprint[..]);
        ret[9..13].copy_from_slice(&self.child_number.first_raw_value().to_be_bytes());
        ret[13..45].copy_from_slice(&self.chain_code[..]);
        ret[45..78].copy_from_slice(&self.public_key.serialize()[..]);
        ret
    }

    /// Returns the HASH160 of the chaincode
    pub fn identifier(&self) -> XpubIdentifier {
        use std::io::Write;

        use bitcoin_hashes::Hash;
        let mut engine = ripemd160::Hash::engine();
        engine.write_all(&self.public_key.serialize()).expect("engines don't error");
        XpubIdentifier::from_engine(engine)
    }

    /// Returns the first four bytes of the identifier
    pub fn fingerprint(&self) -> Fingerprint { self.identifier().into() }
}

mod display_from_str {
    use core::fmt::{self, Display, Formatter};
    use core::str::FromStr;

    use super::*;

    pub enum XkeyParseError {}

    impl Display for Xpub {
        fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
            base58::encode_check_to_fmt(fmt, &self.encode()[..])
        }
    }

    impl FromStr for Xpub {
        type Err = Error;

        fn from_str(inp: &str) -> Result<Xpub, Error> {
            let data = base58::decode_check(inp)?;

            if data.len() != 78 {
                return Err(base58::Error::InvalidLength(data.len()).into());
            }

            Xpub::decode(&data)
        }
    }
}
