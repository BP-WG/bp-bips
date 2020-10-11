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

//! Types, traits & implementations for data structures and interfaces
//! underlying BIP-174 partially-signed bitcoin transaction standard. These
//! types are more generic and can be used outside of the VIP-174 scope for
//! serialization and storage of generic complex key-value maps.

mod error;
mod proprietary_key;
mod typed_key;
mod typed_map;
mod typed_pair;

pub use typed_key::TypedKey;
pub use typed_map::TypedMap;
