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

use PartiallySignedTransaction;
use Error;

pub trait Finalizer {
    fn has_final_info(&self) -> bool;

    fn finalize(&mut self) -> Result<&mut Self, Error>;
}

impl Finalizer for PartiallySignedTransaction {
    fn has_final_info(&self) -> bool {
        unimplemented!()
    }

    fn finalize(&mut self) -> Result<&mut Self, Error> {
        unimplemented!()
    }
}
