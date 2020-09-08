// Rust PSBT Library
// Written by
//   Dr Maxim Orlovsky <orlovsky@pandoracore.com>
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

use std::fmt;

use bitcoin::secp256k1::Signature;

use PartiallySignedTransaction;
use Error;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum VerificationError {
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (self as &fmt::Debug).fmt(f)
    }
}

pub trait Signer {
    fn has_partial_signatures(&self) -> bool;
    fn verify(&self) -> Vec<VerificationError>;

    fn add_signature(&mut self, input: u32, signature: Signature) -> Result<&mut Self, Error>;
}

impl Signer for PartiallySignedTransaction {
    fn has_partial_signatures(&self) -> bool {
        unimplemented!()
    }

    fn verify(&self) -> Vec<VerificationError> {
        unimplemented!()
    }

    fn add_signature(&mut self, input: u32, signature: Signature) -> Result<&mut Self, Error> {
        unimplemented!()
    }
}
