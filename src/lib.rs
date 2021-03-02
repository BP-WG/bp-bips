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

//! # Partially Signed Transactions
//!
//! Implementation of BIP174 Partially Signed Bitcoin Transaction Format as
//! defined at https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
//! except we define PSBTs containing non-standard SigHash types as invalid.

#![recursion_limit = "256"]
#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports,
    dead_code,
    missing_docs,
    warnings
)]

pub mod bip32;
pub mod encoding;
pub mod map;
pub mod raw;
