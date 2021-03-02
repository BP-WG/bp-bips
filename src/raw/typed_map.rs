// Rust library for working with partially signed bitcoin transactions (PSBT)
// Written in 2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the Apache License version 2.0 along with
// this software. If not, see <https://opensource.org/licenses/Apache-2.0>.

//! Data type of BPST key-value maps used by BIP-174

use std::collections::HashSet;

//use crate::raw::typed_key::TypedKey;

pub trait TypeSystem {
    type KeyTypes;
    type Values;
}

pub trait ProprietaryTypes {}

/// Key-value map required for PSBT, as it is defined in BIP-174
pub struct TypedMap<T, P>
where
    T: TypeSystem,
    P: ProprietaryTypes,
{
    /// Known types according to BIP-174
    pub known: HashSet<T>,

    /// Proprietary types
    pub proprietary: HashSet<P>,

    /// Unknown types, i.e. all types which are not standard or proprietary
    /// (they are new standard types from the updated spec)
    pub unknown: HashSet<u8, HashSet<Vec<u8>, Vec<u8>>>,
}

impl<T, P> TypedMap<T, P>
where
    T: TypeSystem,
    P: ProprietaryTypes,
{
    /// Returns value from a proprietary type
    pub fn get(&self) -> &T {
        unimplemented!()
    }
}
