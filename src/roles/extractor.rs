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

use bitcoin::{Transaction, Script};

use PartiallySignedTransaction;
use Error;
use roles::Combiner;

pub trait Extractor {
    fn extract_tx(self) -> Result<Transaction, Error>;
}

impl Extractor for PartiallySignedTransaction {
    /// Extract the Transaction from a PartiallySignedTransaction by filling in
    /// the available signature information in place.
    fn extract_tx(self) -> Result<Transaction, Error> {
        if !self.has_all_signatures() {
            // TODO: Return error
        }

        let mut tx: Transaction = self.global.unsigned_tx;

        for (vin, psbtin) in tx.input.iter_mut().zip(self.inputs.into_iter()) {
            vin.script_sig = psbtin.final_script_sig.unwrap_or_else(Script::new);
            vin.witness = psbtin.final_script_witness.unwrap_or_else(Vec::new);
        }

        Ok(tx)
    }
}
