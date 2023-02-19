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

use core::str::FromStr;

use crate::HdnIdx;

/// Errors in parsing derivation scheme string representation
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Error, Display)]
#[display(doc_comments)]
pub enum ParseError {
    /// invalid blockchain index {0}; it must be either `0h` (bitcoin mainnet) or `1h` (testnets).
    InvalidBlockchain(String),

    /// invalid BIP-43 purpose {0}.
    InvalidPurposeIndex(String),

    /// BIP-{0} support is not implemented (of BIP with this number does not exist).
    UnimplementedBip(u16),

    /// derivation path can't be recognized as one of BIP-43-based standards.
    UnrecognizedBipScheme,

    /// BIP-43 scheme must have form of `bip43/<purpose>h`.
    InvalidBip43Scheme,

    /// BIP-48 scheme must have form of `bip48-native` or `bip48-nested`.
    InvalidBip48Scheme,

    /// invalid derivation path `{0}`.
    InvalidDerivationPath(String),
}

/// Specific derivation scheme after BIP-43 standards
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display)]
#[non_exhaustive]
pub enum Bip43 {
    /// Account-based P2PKH derivation.
    ///
    /// `m / 44' / coin_type' / account'`
    #[display("bip44", alt = "m/44h")]
    Bip44,

    /// Account-based native P2WPKH derivation.
    ///
    /// `m / 84' / coin_type' / account'`
    #[display("bip84", alt = "m/84h")]
    Bip84,

    /// Account-based legacy P2WPH-in-P2SH derivation.
    ///
    /// `m / 49' / coin_type' / account'`
    #[display("bip49", alt = "m/49h")]
    Bip49,

    /// Account-based single-key P2TR derivation.
    ///
    /// `m / 86' / coin_type' / account'`
    #[display("bip86", alt = "m/86h")]
    Bip86,

    /// Cosigner-index-based multisig derivation.
    ///
    /// `m / 45' / cosigner_index
    #[display("bip45", alt = "m/45h")]
    Bip45,

    /// Account-based multisig derivation with sorted keys & P2WSH nested.
    /// scripts
    ///
    /// `m / 48' / coin_type' / account' / 1'`
    #[display("bip48-nested", alt = "m/48h//1h")]
    Bip48Nested,

    /// Account-based multisig derivation with sorted keys & P2WSH native.
    /// scripts
    ///
    /// `m / 48' / coin_type' / account' / 2'`
    #[display("bip48-native", alt = "m/48h//2h")]
    Bip48Native,

    /// Account- & descriptor-based derivation for multi-sig wallets.
    ///
    /// `m / 87' / coin_type' / account'`
    #[display("bip87", alt = "m/87h")]
    Bip87,

    /// Generic BIP43 derivation with custom (non-standard) purpose value.
    ///
    /// `m / purpose'`
    #[display("bip43/{purpose}", alt = "m/{purpose}")]
    Bip43 {
        /// Purpose value
        purpose: HdnIdx,
    },
}

impl FromStr for Bip43 {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_lowercase();
        let bip = s.strip_prefix("bip").or_else(|| s.strip_prefix("m/"));
        Ok(match bip {
            Some("44") => Bip43::Bip44,
            Some("84") => Bip43::Bip84,
            Some("49") => Bip43::Bip49,
            Some("86") => Bip43::Bip86,
            Some("45") => Bip43::Bip45,
            Some(bip48) if bip48.starts_with("48//") => {
                match bip48.strip_prefix("48//").and_then(|index| HdnIdx::from_str(index).ok()) {
                    Some(script_type) if script_type == 1u8 => Bip43::Bip48Nested,
                    Some(script_type) if script_type == 2u8 => Bip43::Bip48Native,
                    _ => {
                        return Err(ParseError::InvalidBip48Scheme);
                    }
                }
            }
            Some("48-nested") => Bip43::Bip48Nested,
            Some("48-native") => Bip43::Bip48Native,
            Some("87") => Bip43::Bip87,
            Some(bip43) if bip43.starts_with("43/") => match bip43.strip_prefix("43/") {
                Some(purpose) => {
                    let purpose = HdnIdx::from_str(purpose)
                        .map_err(|_| ParseError::InvalidPurposeIndex(purpose.to_owned()))?;
                    Bip43::Bip43 { purpose }
                }
                None => return Err(ParseError::InvalidBip43Scheme),
            },
            Some(_) | None => return Err(ParseError::UnrecognizedBipScheme),
        })
    }
}

impl Bip43 {
    /// Constructs derivation standard corresponding to a single-sig P2PKH.
    pub fn singlesig_pkh() -> Bip43 { Bip43::Bip44 }
    /// Constructs derivation standard corresponding to a single-sig
    /// P2WPKH-in-P2SH.
    pub fn singlesig_nested0() -> Bip43 { Bip43::Bip49 }
    /// Constructs derivation standard corresponding to a single-sig P2WPKH.
    pub fn singlesig_segwit0() -> Bip43 { Bip43::Bip84 }
    /// Constructs derivation standard corresponding to a single-sig P2TR.
    pub fn singlesig_taproot() -> Bip43 { Bip43::Bip86 }
    /// Constructs derivation standard corresponding to a multi-sig P2SH BIP45.
    pub fn multisig_ordered_sh() -> Bip43 { Bip43::Bip45 }
    /// Constructs derivation standard corresponding to a multi-sig sorted
    /// P2WSH-in-P2SH.
    pub fn multisig_nested0() -> Bip43 { Bip43::Bip48Nested }
    /// Constructs derivation standard corresponding to a multi-sig sorted
    /// P2WSH.
    pub fn multisig_segwit0() -> Bip43 { Bip43::Bip48Native }
    /// Constructs derivation standard corresponding to a multi-sig BIP87.
    pub fn multisig_descriptor() -> Bip43 { Bip43::Bip87 }
}
