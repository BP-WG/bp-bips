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

use bitcoin::Transaction;

use PartiallySignedTransaction;
use Global;
use Error;

/// Implementation of Creator role according to
/// https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#Creator
pub trait Creator where Self: Sized {
    /// Create a PartiallySignedTransaction from an unsigned transaction, error
    /// if not unsigned.
    ///
    /// Must match implementation from
    /// https://github.com/bitcoin/bitcoin/tree/master/src/psbt.cpp#L9
    fn from_unsigned_tx(tx: Transaction) -> Result<Self, Error>;
}

impl Creator for PartiallySignedTransaction {
    fn from_unsigned_tx(tx: Transaction) -> Result<Self, self::Error> {
        Ok(PartiallySignedTransaction {
            inputs: vec![Default::default(); tx.input.len()],
            // Tracking PR https://github.com/bitcoin/bips/pull/988
            outputs: vec![Default::default(); tx.output.len()],
            global: Global::from_unsigned_tx(tx)?,
        })
    }
}
