// Bitcoin descriptors implementation
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

//! Address-related types for detailed payload analysis and memory-efficient
//! processing.

use core::fmt::{self, Display, Formatter};
use core::str::FromStr;

use amplify::{Array, Bytes32, Wrapper};
use bc::{ScriptPubkey, WitnessVer};
use secp256k1::XOnlyPublicKey;

pub type Bytes20 = Array<u8, 20>;

/// Defines which witness version may have an address.
///
/// The structure is required to support some ambiguity on the witness version
/// used by some address, since `Option<`[`WitnessVersion`]`>` can't cover that
/// ambiguity (see details in [`SegWitInfo::Ambiguous`] description).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SegWitInfo {
    /// P2PKH addresses
    PreSegWit,

    /// P2SH addresses, which may be pre-segwit, segwit v0 (P2WPK/WSH-in-P2SH),
    /// non-taproot segwit v1 wrapped in P2SH, or future segwit versions
    /// wrapped in P2SH bitcoin
    Ambiguous,

    /// Address has a clearly defined segwit version, i.e. P2WPKH, P2WSH, P2TR
    /// or future non-P2SH-wrapped segwit address
    SegWit(WitnessVersion),
}

impl SegWitInfo {
    /// Detects [`WitnessVersion`] used in the current segwit. Returns [`None`]
    /// for both pre-segwit and P2SH (ambiguous) addresses.
    #[inline]
    pub fn witness_version(self) -> Option<WitnessVersion> {
        match self {
            SegWitInfo::PreSegWit => None,
            SegWitInfo::Ambiguous => None,
            SegWitInfo::SegWit(version) => Some(version),
        }
    }
}

/// Bitcoin address.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
pub struct Address {
    /// Address payload (see [`AddressPayload`]).
    pub payload: AddressPayload,

    /// A type of the network used by the address
    pub network: AddressNetwork,
}

impl Address {
    /// Constructs compatible address for a given `scriptPubkey`.
    /// Returns `None` if the uncompressed key is provided or `scriptPubkey`
    /// can't be represented as an address.
    pub fn from_script(script: &ScriptPubkey, network: AddressNetwork) -> Option<Self> {
        Address::from_script(script, network.bitcoin_network())
            .map_err(|_| address::Error::UncompressedPubkey)
            .and_then(Self::try_from)
            .ok()
    }

    /// Returns script corresponding to the given address.
    pub fn script_pubkey(self) -> ScriptPubkey { self.payload.script_pubkey() }

    /// Returns if the address is testnet-, signet- or regtest-specific
    pub fn is_testnet(self) -> bool { self.network != AddressNetwork::Mainnet }
}

impl From<Address> for ScriptPubkey {
    fn from(compact: Address) -> Self { Address::from(compact).script_pubkey().into() }
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { Display::fmt(&Address::from(*self), f) }
}

impl FromStr for Address {
    type Err = address::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Address::from_str(s).and_then(Address::try_from)
    }
}

/// Internal address content. Consists of serialized hashes or x-only key value.
///
/// See also `descriptors::Compact` as a non-copy alternative supporting
/// bare/custom scripts.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[derive(StrictEncode, StrictDecode)]
pub enum AddressPayload {
    /// P2PKH payload.
    #[from]
    #[display("raw_pkh({0})")]
    PubkeyHash(Bytes20),

    /// P2SH and SegWit nested (legacy) P2WPKH/WSH-in-P2SH payloads.
    #[from]
    #[display("raw_sh({0})")]
    ScriptHash(Bytes20),

    /// P2WPKH payload.
    #[from]
    #[display("raw_wpkh({0})")]
    WPubkeyHash(Bytes20),

    /// P2WSH payload.
    #[from]
    #[display("raw_wsh({0})")]
    WScriptHash(Bytes32),

    /// P2TR payload.
    #[from]
    #[display("raw_tr({output_key})")]
    Taproot {
        /// Taproot output key (tweaked key)
        output_key: XOnlyPublicKey,
    },
}

impl AddressPayload {
    /// Constructs [`Address`] from the payload.
    pub fn into_address(self, network: bitcoin::Network) -> Address {
        Address {
            payload: self.into(),
            network,
        }
    }

    /// Constructs payload from a given address. Fails on future (post-taproot)
    /// witness types with `None`.
    pub fn from_address(address: Address) -> Option<Self> { Self::from_payload(address.payload) }

    /// Constructs payload from a given `scriptPubkey`. Fails on future (post-taproot) witness types
    /// with `None`.
    pub fn from_script_pubkey(_script: &ScriptPubkey) -> Option<Self> { todo!() }

    /// Returns script corresponding to the given address.
    pub fn into_script_pubkey(self) -> ScriptPubkey { todo!() }
}

impl From<AddressPayload> for ScriptPubkey {
    fn from(payload: AddressPayload) -> Self { payload.into_script_pubkey() }
}

/// Errors parsing address strings.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum AddressParseError {
    /// unknown address payload prefix `{0}`; expected `pkh`, `sh`, `wpkh`,
    /// `wsh` and `pkxo` only
    UnknownPrefix(String),

    /// unrecognized address payload string format
    UnrecognizedStringFormat,

    /// address payload must be prefixed by pyaload format prefix, indicating
    /// specific form of hash or a public key used inside the address
    PrefixAbsent,

    /// wrong address payload data
    #[from(hex::Error)]
    WrongPayloadHashData,

    /// wrong BIP340 public key (xcoord-only)
    #[from(secp256k1::Error)]
    WrongPublicKeyData,

    /// unrecognized address network string; only `mainnet`, `testnet` and
    /// `regtest` are possible at address level
    UnrecognizedAddressNetwork,

    /// unrecognized address format string; must be one of `P2PKH`, `P2SH`,
    /// `P2WPKH`, `P2WSH`, `P2TR`
    UnrecognizedAddressFormat,

    /// wrong witness version
    WrongWitnessVersion,
}

impl FromStr for AddressPayload {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> { todo!() }
}

/// Address format
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum AddressFormat {
    /// Pay-to-public key hash
    #[display("P2PKH")]
    P2pkh,

    /// Pay-to-script hash
    #[display("P2SH")]
    P2sh,

    /// Pay-to-witness public key hash
    #[display("P2WPKH")]
    P2wpkh,

    /// Pay-to-witness script pash
    #[display("P2WSH")]
    P2wsh,

    /// Pay-to-taproot
    #[display("P2TR")]
    P2tr,

    /// Future witness address
    #[display("P2W{0}")]
    Future(WitnessVer),
}

impl AddressFormat {
    /// Returns witness version used by the address format.
    /// Returns `None` for pre-SegWit address formats.
    pub fn witness_ver(self) -> Option<WitnessVer> {
        match self {
            AddressFormat::P2pkh => None,
            AddressFormat::P2sh => None,
            AddressFormat::P2wpkh | AddressFormat::P2wsh => Some(WitnessVersion::V0),
            AddressFormat::P2tr => Some(WitnessVersion::V1),
            AddressFormat::Future(ver) => Some(ver),
        }
    }
}

impl From<Address> for AddressFormat {
    fn from(address: Address) -> Self { address.payload.into() }
}

impl From<Payload> for AddressFormat {
    fn from(payload: Payload) -> Self {
        match payload {
            Payload::PubkeyHash(_) => AddressFormat::P2pkh,
            Payload::ScriptHash(_) => AddressFormat::P2sh,
            Payload::WitnessProgram { version, program }
                if version.to_num() == 0 && program.len() == 32 =>
            {
                AddressFormat::P2wsh
            }
            Payload::WitnessProgram { version, program }
                if version.to_num() == 0 && program.len() == 20 =>
            {
                AddressFormat::P2wpkh
            }
            Payload::WitnessProgram { version, .. } if version.to_num() == 1 => AddressFormat::P2tr,
            Payload::WitnessProgram { version, .. } => AddressFormat::Future(version),
        }
    }
}

impl FromStr for AddressFormat {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        #[allow(clippy::match_str_case_mismatch)]
        Ok(match s.to_uppercase().as_str() {
            "P2PKH" => AddressFormat::P2pkh,
            "P2SH" => AddressFormat::P2sh,
            "P2WPKH" => AddressFormat::P2wpkh,
            "P2WSH" => AddressFormat::P2wsh,
            "P2TR" => AddressFormat::P2tr,
            s if s.starts_with("P2W") => AddressFormat::Future(
                WitnessVersion::from_str(&s[3..])
                    .map_err(|_| AddressParseError::WrongWitnessVersion)?,
            ),
            _ => return Err(AddressParseError::UnrecognizedAddressFormat),
        })
    }
}

/// Bitcoin network used by the address
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
pub enum AddressNetwork {
    /// Bitcoin mainnet
    #[display("mainnet")]
    Mainnet,

    /// Bitcoin testnet and signet
    #[display("testnet")]
    Testnet,

    /// Bitcoin regtest networks
    #[display("regtest")]
    Regtest,
}

impl FromStr for AddressNetwork {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "mainnet" => AddressNetwork::Mainnet,
            "testnet" => AddressNetwork::Testnet,
            "regtest" => AddressNetwork::Regtest,
            _ => return Err(AddressParseError::UnrecognizedAddressNetwork),
        })
    }
}

impl From<Address> for AddressNetwork {
    fn from(address: Address) -> Self { address.network.into() }
}

impl From<bitcoin::Network> for AddressNetwork {
    fn from(network: bitcoin::Network) -> Self {
        match network {
            bitcoin::Network::Bitcoin => AddressNetwork::Mainnet,
            bitcoin::Network::Testnet => AddressNetwork::Testnet,
            bitcoin::Network::Signet => AddressNetwork::Testnet,
            bitcoin::Network::Regtest => AddressNetwork::Regtest,
        }
    }
}

impl AddressNetwork {
    /// This convertor is not public since there is an ambiguity which type
    /// must correspond to the [`AddressNetwork::Testnet`]. Thus, clients of
    /// this library must propvide their custom convertors taking decisions
    /// on this question.
    fn bitcoin_network(self) -> bitcoin::Network {
        match self {
            AddressNetwork::Mainnet => bitcoin::Network::Bitcoin,
            AddressNetwork::Testnet => bitcoin::Network::Testnet,
            AddressNetwork::Regtest => bitcoin::Network::Regtest,
        }
    }

    /// Detects whether the network is a kind of test network (testnet, signet,
    /// regtest).
    pub fn is_testnet(self) -> bool { self != Self::Mainnet }
}
