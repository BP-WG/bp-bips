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

use core::cmp::Ordering;
use core::fmt::{self, Display, Formatter};
use core::str::FromStr;

use self::index_error::*;

/// Constant determining BIP32 boundary for u32 values starting from which index is treated as
/// hardened.
pub const HARDENED_INDEX_BOUNDARY: u32 = 1 << 31;

// TODO: Implement iterator methods

pub mod index_error {
    use core::num::ParseIntError;

    use super::*;

    /// Error happening when a hardened or unhardened index is constructed from integer index value
    /// overflowing [`HARDENED_INDEX_BOUNDARY`].
    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Display, Error)]
    #[display(
        "invalid derivation index {0} overflowing 2^31. Perhaps you need to use hardened \
         constructor instead of index value?"
    )]
    pub struct IndexOverflow(pub u32);

    /// Errors if an unsupported index type is expected from a type implementing
    /// [`DerivationIndex`].
    #[derive(Copy, Clone, Eq, PartialEq, Debug, Display, From, Error)]
    #[display(inner)]
    pub enum IndexUnsupported {
        /// Unhardened index met when hardened was expected.
        #[from]
        Unhardened(HdnIdxExpected),

        /// Hardened index met when unhardened was expected.
        #[from]
        Hardened(NormIdxExpected),
    }

    /// normal derivation index {0} met when a hardened index was required.
    #[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Display, From, Error)]
    #[display(doc_comments)]
    pub struct HdnIdxExpected(pub NormIdx);

    /// hardened derivation index {0} met when a normal (unhardened) index was required.
    #[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Display, From, Error)]
    #[display(doc_comments)]
    pub struct NormIdxExpected(pub HdnIdx);

    /// Errors parsing string indexes from string.
    #[derive(Clone, Eq, PartialEq, Debug, Display, From, Error)]
    #[display(inner)]
    pub enum IndexParseError {
        /// Invalid index integer value
        #[from]
        InvalidInt(ParseIntError),

        /// Index value overflow over [`HARDENED_INDEX_BOUNDARY`].
        #[from]
        Overflow(IndexOverflow),

        /// Unsupported index type.
        #[from]
        #[from(HdnIdxExpected)]
        #[from(NormIdxExpected)]
        Unsupported(IndexUnsupported),
    }
}

/// Trait defining common API for different types of indexes which may be
/// present in a certain derivation path segment: hardened, unhardened, mixed.
pub trait DerivationIndex
where Self: Copy + Ord
{
    /// Constructs derivation path segment with index equal to zero
    fn zero() -> Self;

    /// Constructs derivation path segment with index equal to one
    fn one() -> Self;

    /// Constructs derivation path segment with index equal to maximum value
    fn largest() -> Self;

    /// Counts number of derivation indexes in this derivation path segment
    fn count(&self) -> usize;

    /// Detects if a given index may be used at this derivation segment
    fn contains(&self, index: u32) -> bool;

    /// Constructs derivation path segment with specific index.
    ///
    /// Index is always a value in range of `0..`[`HARDENED_INDEX_BOUNDARY`]
    fn from_index(index: impl Into<u32>) -> Result<Self, IndexOverflow>;

    /// Returns index representation of this derivation path segment. If
    /// derivation path segment contains multiple indexes, returns the value of
    /// the first one.
    ///
    /// Index is always a value in range of `0..`[`HARDENED_INDEX_BOUNDARY`]
    fn first_index(&self) -> u32;

    /// Returns index representation of this derivation path segment. If
    /// derivation path segment contains multiple indexes, returns the value of
    /// the last one; otherwise equal to [`DerivationIndex::first_index`];
    ///
    /// Index is always a value in range of `0..`[`HARDENED_INDEX_BOUNDARY`]
    #[inline]
    fn last_index(&self) -> u32 { self.first_index() }

    /// Constructs derivation path segment with specific derivation value, which
    /// for normal indexes must lie in range `0..`[`HARDENED_INDEX_BOUNDARY`]
    /// and for hardened in range of [`HARDENED_INDEX_BOUNDARY`]`..=u32::MAX`.
    ///
    /// Errors if applied to an index type not supporting hardener or unharneded
    /// indexes.
    fn from_raw_value(value: u32) -> Result<Self, IndexUnsupported>;

    /// Returns value used during derivation, which for normal indexes must lie
    /// in range `0..`[`HARDENED_INDEX_BOUNDARY`] and for hardened in range
    /// of [`HARDENED_INDEX_BOUNDARY`]`..=u32::MAX`
    fn first_raw_value(&self) -> u32;

    /// Returns value used during derivation, which for normal indexes must lie
    /// in range `0..`[`HARDENED_INDEX_BOUNDARY`] and for hardened in range
    /// of [`HARDENED_INDEX_BOUNDARY`]`..=u32::MAX`.
    ///
    /// If the path segment consist of the single index value, this function is
    /// equal to [`DerivationIndex::first_raw_value`]
    #[inline]
    fn last_derivation_value(&self) -> u32 { self.first_raw_value() }

    /// Increases the index on one step; fails if the index value is already
    /// maximum value - or if multiple indexes are present at the path segment
    fn checked_inc(&self) -> Option<Self> { self.checked_add(1u8) }

    /// Decreases the index on one step; fails if the index value is already
    /// minimum value - or if multiple indexes are present at the path segment
    fn checked_dec(&self) -> Option<Self> { self.checked_sub(1u8) }

    /// Mutates the self by increasing the index on one step; fails if the index
    /// value is already maximum value - or if multiple indexes are present at
    /// the path segment
    fn checked_inc_assign(&mut self) -> Option<u32> { self.checked_add_assign(1u8) }

    /// Mutates the self by decreasing the index on one step; fails if the index
    /// value is already maximum value - or if multiple indexes are present at
    /// the path segment
    fn checked_dec_assign(&mut self) -> Option<u32> { self.checked_sub_assign(1u8) }

    /// Adds value the index; fails if the index value overflow happens - or if
    /// multiple indexes are present at the path segment
    fn checked_add(&self, add: impl Into<u32>) -> Option<Self> {
        let mut res = self.clone();
        res.checked_add_assign(add)?;
        Some(res)
    }

    /// Subtracts value the index; fails if the index value overflow happens -
    /// or if multiple indexes are present at the path segment
    fn checked_sub(&self, sub: impl Into<u32>) -> Option<Self> {
        let mut res = self.clone();
        res.checked_sub_assign(sub)?;
        Some(res)
    }

    /// Mutates the self by adding value the index; fails if the index value
    /// overflow happens - or if multiple indexes are present at the path
    /// segment
    fn checked_add_assign(&mut self, add: impl Into<u32>) -> Option<u32>;

    /// Mutates the self by subtracting value the index; fails if the index
    /// value overflow happens - or if multiple indexes are present at the
    /// path segment
    fn checked_sub_assign(&mut self, sub: impl Into<u32>) -> Option<u32>;

    /// Detects whether path segment uses hardened index(es)
    fn is_hardened(&self) -> bool;
}

fn checked_add_assign(index: &mut u32, add: impl Into<u32>) -> Option<u32> {
    let add: u32 = add.into();
    *index = index.checked_add(add)?;
    if *index >= HARDENED_INDEX_BOUNDARY {
        return None;
    }
    Some(*index)
}

fn checked_sub_assign(index: &mut u32, sub: impl Into<u32>) -> Option<u32> {
    let sub: u32 = sub.into();
    *index = index.checked_sub(sub)?;
    Some(*index)
}

// -----------------------------------------------------------------------------

/// Index for unhardened children derivation; ensures that the inner value
/// is always < 2^31
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Default, Display, From)]
#[display(inner)]
pub struct NormIdx(
    #[from(u8)]
    #[from(u16)]
    u32,
);

impl PartialEq<u8> for NormIdx {
    fn eq(&self, other: &u8) -> bool { self.0 == *other as u32 }
}

impl PartialEq<u16> for NormIdx {
    fn eq(&self, other: &u16) -> bool { self.0 == *other as u32 }
}

impl PartialOrd<u8> for NormIdx {
    fn partial_cmp(&self, other: &u8) -> Option<Ordering> { self.0.partial_cmp(&(*other as u32)) }
}

impl PartialOrd<u16> for NormIdx {
    fn partial_cmp(&self, other: &u16) -> Option<Ordering> { self.0.partial_cmp(&(*other as u32)) }
}

impl DerivationIndex for NormIdx {
    #[inline]
    fn zero() -> Self { NormIdx(0) }

    #[inline]
    fn one() -> Self { NormIdx(1) }

    #[inline]
    fn largest() -> Self { NormIdx(HARDENED_INDEX_BOUNDARY - 1) }

    #[inline]
    fn count(&self) -> usize { 1 }

    #[inline]
    fn contains(&self, index: u32) -> bool { self.0 == index }

    #[inline]
    fn from_index(index: impl Into<u32>) -> Result<Self, IndexOverflow> {
        let index = index.into();
        if index >= HARDENED_INDEX_BOUNDARY {
            Err(IndexOverflow(index))
        } else {
            Ok(Self(index))
        }
    }

    /// Returns unhardened index number.
    #[inline]
    fn first_index(&self) -> u32 { self.0 }

    #[inline]
    fn from_raw_value(value: u32) -> Result<Self, IndexUnsupported> {
        if value < HARDENED_INDEX_BOUNDARY {
            Ok(NormIdx(value).into())
        } else {
            Err(NormIdxExpected(HdnIdx(value)).into())
        }
    }

    #[inline]
    fn first_raw_value(&self) -> u32 { self.first_index() }

    #[inline]
    fn checked_add_assign(&mut self, add: impl Into<u32>) -> Option<u32> {
        checked_add_assign(&mut self.0, add)
    }

    #[inline]
    fn checked_sub_assign(&mut self, sub: impl Into<u32>) -> Option<u32> {
        checked_sub_assign(&mut self.0, sub)
    }

    #[inline]
    fn is_hardened(&self) -> bool { false }
}

impl FromStr for NormIdx {
    type Err = IndexParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        NormIdx::from_index(u32::from_str(s)?).map_err(IndexParseError::from)
    }
}

impl TryFrom<ChildIdx> for NormIdx {
    type Error = NormIdxExpected;

    fn try_from(value: ChildIdx) -> Result<Self, Self::Error> {
        match value {
            ChildIdx::Normal(index) => Ok(index),
            ChildIdx::Hardened(index) => Err(NormIdxExpected(index)),
        }
    }
}

/// Index for hardened children derivation; ensures that the index always >= 2^31.
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default, Display, From)]
#[display("{0}h", alt = "{0}'")]
pub struct HdnIdx(
    /// The inner index value; always reduced by [`HARDENED_INDEX_BOUNDARY`]
    #[from(u8)]
    #[from(u16)]
    u32,
);

impl PartialEq<u8> for HdnIdx {
    fn eq(&self, other: &u8) -> bool { self.0 == *other as u32 }
}

impl PartialEq<u16> for HdnIdx {
    fn eq(&self, other: &u16) -> bool { self.0 == *other as u32 }
}

impl PartialOrd<u8> for HdnIdx {
    fn partial_cmp(&self, other: &u8) -> Option<Ordering> { self.0.partial_cmp(&(*other as u32)) }
}

impl PartialOrd<u16> for HdnIdx {
    fn partial_cmp(&self, other: &u16) -> Option<Ordering> { self.0.partial_cmp(&(*other as u32)) }
}

impl DerivationIndex for HdnIdx {
    #[inline]
    fn zero() -> Self { HdnIdx(0) }

    #[inline]
    fn one() -> Self { HdnIdx(1) }

    #[inline]
    fn largest() -> Self { HdnIdx(HARDENED_INDEX_BOUNDARY - 1) }

    #[inline]
    fn count(&self) -> usize { 1 }

    #[inline]
    fn contains(&self, index: u32) -> bool { self.0 == index }

    #[inline]
    fn from_index(index: impl Into<u32>) -> Result<Self, IndexOverflow> {
        let index = index.into();
        if index >= HARDENED_INDEX_BOUNDARY {
            Ok(Self(index - HARDENED_INDEX_BOUNDARY))
        } else {
            Ok(Self(index))
        }
    }

    /// Returns hardened index number offset by [`HARDENED_INDEX_BOUNDARY`]
    /// (i.e. zero-based).
    #[inline]
    fn first_index(&self) -> u32 { self.0 }

    #[inline]
    fn from_raw_value(value: u32) -> Result<Self, IndexUnsupported> {
        if value < HARDENED_INDEX_BOUNDARY {
            Err(HdnIdxExpected(NormIdx(value)).into())
        } else {
            Ok(Self(value - HARDENED_INDEX_BOUNDARY))
        }
    }

    #[inline]
    fn first_raw_value(&self) -> u32 { self.0 + HARDENED_INDEX_BOUNDARY }

    #[inline]
    fn checked_add_assign(&mut self, add: impl Into<u32>) -> Option<u32> {
        checked_add_assign(&mut self.0, add)
    }

    #[inline]
    fn checked_sub_assign(&mut self, sub: impl Into<u32>) -> Option<u32> {
        checked_sub_assign(&mut self.0, sub)
    }

    #[inline]
    fn is_hardened(&self) -> bool { true }
}

impl FromStr for HdnIdx {
    type Err = IndexParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(idx) = s.strip_suffix(['h', 'H', '\'']) {
            Ok(HdnIdx(u32::from_str(idx)?))
        } else {
            Err(HdnIdxExpected(NormIdx::from_str(s)?).into())
        }
    }
}

impl TryFrom<ChildIdx> for HdnIdx {
    type Error = HdnIdxExpected;

    fn try_from(value: ChildIdx) -> Result<Self, Self::Error> {
        match value {
            ChildIdx::Normal(index) => Err(HdnIdxExpected(index)),
            ChildIdx::Hardened(index) => Ok(index),
        }
    }
}

// -----------------------------------------------------------------------------

/// Derivation segment for the account part of the derivation path as defined by
/// LNPBP-32 standard
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From)]
pub enum ChildIdx {
    /// Derivation segment is defined by a single unhardened index
    #[from(u8)]
    #[from(u16)]
    #[from]
    Normal(NormIdx),

    /// Derivation segment is defined by a hardened index
    #[from]
    Hardened(HdnIdx),
}

impl ChildIdx {
    /// Constructs [`ChildIdx`] with u16 value interpreted as a [`HdnIdx::from`] parameter – and no
    /// extended public key reference.
    #[inline]
    pub fn hardened_index(index: impl Into<u16>) -> Self {
        Self::Hardened(HdnIdx::from(index.into()))
    }
}

impl DerivationIndex for ChildIdx {
    #[inline]
    fn zero() -> Self { ChildIdx::Hardened(HdnIdx::zero()) }

    #[inline]
    fn one() -> Self { ChildIdx::Hardened(HdnIdx::one()) }

    #[inline]
    fn largest() -> Self { ChildIdx::Hardened(HdnIdx::largest()) }

    #[inline]
    fn count(&self) -> usize { 1 }

    #[inline]
    fn contains(&self, i: u32) -> bool {
        match self {
            ChildIdx::Normal(index) => index.contains(i),
            ChildIdx::Hardened(index) => index.contains(i | HARDENED_INDEX_BOUNDARY),
        }
    }

    fn from_index(index: impl Into<u32>) -> Result<Self, IndexOverflow> {
        let index = index.into();
        Ok(NormIdx::from_index(index).map(Self::Normal).unwrap_or_else(|_| {
            Self::Hardened(
                HdnIdx::from_index(index).expect("index is either hardened or unhardened"),
            )
        }))
    }

    #[inline]
    fn first_index(&self) -> u32 {
        match self {
            ChildIdx::Normal(index) => DerivationIndex::first_index(index),
            ChildIdx::Hardened(index) => DerivationIndex::first_index(index),
        }
    }

    #[inline]
    fn from_raw_value(value: u32) -> Result<Self, IndexUnsupported> {
        if value < HARDENED_INDEX_BOUNDARY {
            Ok(NormIdx(value).into())
        } else {
            Ok(HdnIdx(value).into())
        }
    }

    #[inline]
    fn first_raw_value(&self) -> u32 {
        match self {
            ChildIdx::Normal(index) => index.first_raw_value(),
            ChildIdx::Hardened(index) => index.first_raw_value(),
        }
    }

    #[inline]
    fn checked_add_assign(&mut self, add: impl Into<u32>) -> Option<u32> {
        match self {
            ChildIdx::Normal(index) => index.checked_add_assign(add),
            ChildIdx::Hardened(index) => index.checked_add_assign(add),
        }
    }

    #[inline]
    fn checked_sub_assign(&mut self, sub: impl Into<u32>) -> Option<u32> {
        match self {
            ChildIdx::Normal(index) => index.checked_sub_assign(sub),
            ChildIdx::Hardened(index) => index.checked_sub_assign(sub),
        }
    }

    #[inline]
    fn is_hardened(&self) -> bool {
        match self {
            ChildIdx::Normal { .. } => false,
            ChildIdx::Hardened { .. } => true,
        }
    }
}

impl Display for ChildIdx {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ChildIdx::Normal(index) => Display::fmt(index, f),
            ChildIdx::Hardened(index) => Display::fmt(index, f),
        }
    }
}

impl FromStr for ChildIdx {
    type Err = IndexParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.ends_with(['h', 'H', '\'']) {
            HdnIdx::from_str(s).map(ChildIdx::Hardened)
        } else {
            NormIdx::from_str(s).map(ChildIdx::Normal)
        }
    }
}
