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
use base58::FromBase58Error;

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

/// Length of the extended key binary representation.
pub const XKEY_LEN: usize = 78;

/// Errors decoding extended key from a binary BIP32 encoding.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum XkeyDecodeError {
    /// invalid extended key length ({0} instead of 78).
    InvalidLen(usize),
    /// invalid key data in the extended key ({0}).
    InvalidKey(Array<u8, 33>),
}

/// Errors decoding extended key from a Base58 string representation.
#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum XkeyParseError {
    /// The input contained a character which is not a part of the base58 format.
    InvalidBase58Character(char, usize),

    /// The input had invalid length.
    InvalidBase58Length,

    /// invalid extended key Base58 encoded length ({0} instead of 82).
    InvalidLen(usize),

    /// invalid extended key Base58 checksum (expected {expected:x}, found {actual:x}).
    InvalidChecksum {
        expected: Array<u8, 4>,
        actual: Array<u8, 4>,
    },

    #[from]
    #[display(inner)]
    Decode(XkeyDecodeError),
}

impl From<FromBase58Error> for XkeyParseError {
    fn from(err: FromBase58Error) -> Self {
        match err {
            FromBase58Error::InvalidBase58Character(a, b) => Self::InvalidBase58Character(a, b),
            FromBase58Error::InvalidBase58Length => Self::InvalidBase58Length,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
/// derivation is impossible: the depth of the current key has reached maximum (255).
pub struct TooDeepDerivation;
