// Rust Bitcoin Library
// Written by
//   The Rust Bitcoin developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # PSBT Serialization
//!
//! Defines traits used for (de)serializing PSBT values into/from raw
//! bytes in PSBT key-value pairs.

use std::io;

use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::{SigHashType, Transaction, TxOut};
use bitcoin::consensus::encode::{self, serialize, Decodable};
use bitcoin::util::bip32::{ChildNumber, DerivationPath, Fingerprint};
use bitcoin::util::key::PublicKey;
use Error;


/// Data which can be encoded in a consensus-consistent way
pub trait Encode {
    /// Encode an object with a well-defined format, should only ever error if
    /// the underlying `Write` errors. Returns the number of bytes written on
    /// success
    fn encode<W: io::Write>(&self, e: W) -> Result<usize, Error>;
}

/// Data which can be encoded in a consensus-consistent way
pub trait Decode: Sized {
    /// Decode an object with a well-defined format
    fn decode<D: io::Read>(d: D) -> Result<Self, Error>;
}


/// A trait for serializing a value as raw data for insertion into PSBT
/// key-value pairs.
pub trait Serialize {
    /// Serialize a value as raw data.
    fn serialize(&self) -> Vec<u8>;
}

/// A trait for deserializing a value from raw data in PSBT key-value pairs.
pub trait Deserialize: Sized {
    /// Deserialize a value from raw data.
    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;
}

impl_psbt_de_serialize!(Transaction);
impl_psbt_de_serialize!(TxOut);
impl_psbt_de_serialize!(Vec<Vec<u8>>); // scriptWitness

impl Serialize for Script {
    fn serialize(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl Deserialize for Script {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from(bytes.to_vec()))
    }
}

impl Serialize for PublicKey {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_into(&mut buf);
        buf
    }
}

impl Deserialize for PublicKey {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        PublicKey::from_slice(bytes)
            .map_err(|_| Error::InvalidPubkey(bytes.to_vec()))
    }
}

impl Serialize for (Fingerprint, DerivationPath) {
    fn serialize(&self) -> Vec<u8> {
        let mut rv: Vec<u8> = Vec::with_capacity(4 + 4 * (self.1).as_ref().len());

        rv.append(&mut self.0.to_bytes().to_vec());

        for cnum in self.1.into_iter() {
            rv.append(&mut serialize(&u32::from(*cnum)))
        }

        rv
    }
}

impl Deserialize for (Fingerprint, DerivationPath) {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 4 {
            return Err(Error::UnexpectedEof)
        }

        let fprint: Fingerprint = Fingerprint::from(&bytes[0..4]);
        let mut dpath: Vec<ChildNumber> = Default::default();

        let mut d = &bytes[4..];
        while !d.is_empty() {
            match u32::consensus_decode(&mut d) {
                Ok(index) => dpath.push(index.into()),
                Err(e) => return Err(Error::ConsensusEncoding(e)),
            }
        }

        Ok((fprint, dpath.into()))
    }
}

// partial sigs
impl Serialize for Vec<u8> {
    fn serialize(&self) -> Vec<u8> {
        self.clone()
    }
}

impl Deserialize for Vec<u8> {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Ok(bytes.to_vec())
    }
}

impl Serialize for SigHashType {
    fn serialize(&self) -> Vec<u8> {
        serialize(&self.as_u32())
    }
}

impl Deserialize for SigHashType {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let raw: u32 = encode::deserialize(bytes)?;
        let rv: SigHashType = SigHashType::from_u32(raw);

        if rv.as_u32() == raw {
            Ok(rv)
        } else {
            Err(Error::NonStandardSigHashType(raw).into())
        }
    }
}
