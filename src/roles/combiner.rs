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

use Global;
use Input;
use Output;
use PartiallySignedTransaction;
use Error;

pub trait Combiner {
    fn has_all_signatures(&self) -> bool;

    fn merge(&mut self, other: Self) -> Result<(), Error>;
}

impl Combiner for PartiallySignedTransaction {
    fn has_all_signatures(&self) -> bool {
        unimplemented!()
    }

    /// Attempt to merge with another `PartiallySignedTransaction`.
    fn merge(&mut self, other: Self) -> Result<(), Error> {
        self.global.merge(other.global)?;

        for (self_input, other_input) in self.inputs.iter_mut().zip(other.inputs.into_iter()) {
            self_input.merge(other_input)?;
        }

        for (self_output, other_output) in self.outputs.iter_mut().zip(other.outputs.into_iter()) {
            self_output.merge(other_output)?;
        }

        Ok(())
    }
}

impl Combiner for Global {
    fn has_all_signatures(&self) -> bool {
        unimplemented!()
    }

    fn merge(&mut self, other: Self) -> Result<(), Error> {
        if self.unsigned_tx != other.unsigned_tx {
            return Err(Error::UnexpectedUnsignedTx {
                expected: self.unsigned_tx.clone(),
                actual: other.unsigned_tx,
            });
        }

        self.unknown.extend(other.unknown);
        Ok(())
    }
}

impl Combiner for Input {
    fn has_all_signatures(&self) -> bool {
        unimplemented!()
    }

    fn merge(&mut self, other: Self) -> Result<(), Error> {
        merge!(non_witness_utxo, self, other);

        if let (&None, Some(witness_utxo)) = (&self.witness_utxo, other.witness_utxo) {
            self.witness_utxo = Some(witness_utxo);
            self.non_witness_utxo = None; // Clear out any non-witness UTXO when we set a witness one
        }

        self.partial_sigs.extend(other.partial_sigs);
        self.hd_keypaths.extend(other.hd_keypaths);
        self.unknown.extend(other.unknown);

        merge!(redeem_script, self, other);
        merge!(witness_script, self, other);
        merge!(final_script_sig, self, other);
        merge!(final_script_witness, self, other);

        Ok(())
    }
}

impl Combiner for Output {
    fn has_all_signatures(&self) -> bool {
        unimplemented!()
    }

    fn merge(&mut self, other: Self) -> Result<(), Error> {
        self.hd_keypaths.extend(other.hd_keypaths);
        self.unknown.extend(other.unknown);

        merge!(redeem_script, self, other);
        merge!(witness_script, self, other);

        Ok(())
    }
}
