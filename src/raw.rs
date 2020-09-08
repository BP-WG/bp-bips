// Rust PSBT Library
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

//! # Raw PSBT Key-Value Pairs
//!
//! Raw PSBT key-value pairs as defined at
//! https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki.

use std::{fmt, io};

use bitcoin::consensus::encode::{self, ReadExt, WriteExt, Decodable, Encodable, VarInt, MAX_VEC_SIZE};
use bitcoin::hashes::hex::ToHex;

use Error;
use serialize::{Encode, Decode, serialize, deserialize};

/// A PSBT key in its raw byte form.
#[derive(Debug, PartialEq, Hash, Eq, Clone, Ord, PartialOrd)]
pub struct Key {
    /// The type of this PSBT key.
    pub type_value: u8,
    /// The key itself in raw byte form.
    pub key: Vec<u8>,
}

/// A PSBT key-value pair in its raw byte form.
#[derive(Debug, PartialEq)]
pub struct Pair {
    /// The key of this key-value pair.
    pub key: Key,
    /// The value of this key-value pair in raw byte form.
    pub value: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ProprietaryType;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ProprietaryKey<Subtype = ProprietaryType> where Subtype: Copy + From<u8> + Into<u8> {
    pub prefix: Vec<u8>,
    pub subtype: Subtype,
    pub key: Vec<u8>,
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "type: {:#x}, key: {}",
            self.type_value,
            self.key[..].to_hex()
        )
    }
}

impl Decode for Key {
    fn decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let VarInt(byte_size): VarInt = Decodable::consensus_decode(&mut d)?;

        if byte_size == 0 {
            return Err(Error::NoMorePairs.into());
        }

        let key_byte_size: u64 = byte_size - 1;

        if key_byte_size > MAX_VEC_SIZE as u64 {
            return Err(Error::ConsensusEncoding(encode::Error::OversizedVectorAllocation {
                requested: key_byte_size as usize,
                max: MAX_VEC_SIZE,
            }))
        }

        let type_value: u8 = Decodable::consensus_decode(&mut d)?;

        let mut key = Vec::with_capacity(key_byte_size as usize);
        for _ in 0..key_byte_size {
            key.push(Decodable::consensus_decode(&mut d)?);
        }

        Ok(Key {
            type_value: type_value,
            key: key,
        })
    }
}

impl Encode for Key {
    fn encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, Error> {
        let mut len = 0;
        len += VarInt((self.key.len() + 1) as u64).consensus_encode(&mut s)?;

        len += self.type_value.consensus_encode(&mut s)?;

        for key in &self.key {
            len += key.consensus_encode(&mut s)?
        }

        Ok(len)
    }
}

impl Encode for Pair {
    fn encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, Error> {
        let len = self.key.encode(&mut s)?;
        Ok(len + self.value.consensus_encode(s)?)
    }
}

impl Decode for Pair {
    fn decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(Pair {
            key: Decode::decode(&mut d)?,
            value: Decodable::consensus_decode(d)?,
        })
    }
}

impl From<u8> for ProprietaryType {
    fn from(_: u8) -> Self {
        ProprietaryType
    }
}

impl Into<u8> for ProprietaryType {
    fn into(self) -> u8 {
        0u8
    }
}

impl<Subtype> Encode for ProprietaryKey<Subtype> where Subtype: Copy + From<u8> + Into<u8> {
    fn encode<W: io::Write>(&self, mut e: W) -> Result<usize, Error> {
        let mut len = self.prefix.consensus_encode(&mut e)? + 1;
        e.emit_u8(self.subtype.into())?;
        len += e.write(&self.key)?;
        Ok(len)
    }
}

impl<Subtype> Decode for ProprietaryKey<Subtype> where Subtype: Copy + From<u8> + Into<u8> {
    fn decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let VarInt(prefix_size) = VarInt::consensus_decode(&mut d)?;

        let mut prefix = vec![0u8; prefix_size as usize];
        let mut key = vec![];
        d.read_exact(&mut prefix)?;
        let subtype = Subtype::from(d.read_u8()?);
        d.read_to_end(&mut key)?;

        Ok(ProprietaryKey {
            prefix,
            subtype,
            key
        })
    }
}

impl<Subtype> ProprietaryKey<Subtype> where Subtype: Copy + From<u8> + Into<u8> {
    pub fn from_key(key: Key) -> Result<Self, Error> {
        if key.type_value != 0xFC {
            return Err(Error::InvalidProprietaryKey)
        }

        deserialize(&key.key)
    }

    pub fn into_key(self) -> Key {
        Key {
            type_value: 0xFC,
            key: serialize(&self)
        }
    }
}
