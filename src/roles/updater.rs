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

use bitcoin::{Transaction, TxIn, Script};
use bitcoin::util::bip32::{DerivationPath, Fingerprint};

use PartiallySignedTransaction;
use Error;

pub trait Updater {
    fn has_sign_info(&self) -> bool;

    fn add_input_tx(&mut self, index: u32, tx: &Transaction) -> Result<&mut Self, Error>;
    fn add_input_utxo(&mut self, index: u32, txin: &TxIn) -> Result<&mut Self, Error>;
    fn add_input_script(&mut self, index: u32, script: &Script) -> Result<&mut Self, Error>;
    fn add_input_wscript(&mut self, index: u32, script: &Script) -> Result<&mut Self, Error>;
    fn add_input_derivation(&mut self, index: u32, fingerprint: Fingerprint, path: &DerivationPath) -> Result<&mut Self, Error>;

    fn add_output_script(&mut self, index: u32, script: &Script) -> Result<&mut Self, Error>;
    fn add_output_wscript(&mut self, index: u32, script: &Script) -> Result<&mut Self, Error>;
    fn add_output_derivation(&mut self, index: u32, fingerprint: Fingerprint, path: &DerivationPath) -> Result<&mut Self, Error>;
}

impl Updater for PartiallySignedTransaction {
    fn has_sign_info(&self) -> bool {
        unimplemented!()
    }

    fn add_input_tx(&mut self, index: u32, tx: &Transaction) -> Result<&mut Self, Error> {
        unimplemented!()
    }

    fn add_input_utxo(&mut self, index: u32, txin: &TxIn) -> Result<&mut Self, Error> {
        unimplemented!()
    }

    fn add_input_script(&mut self, index: u32, script: &Script) -> Result<&mut Self, Error> {
        unimplemented!()
    }

    fn add_input_wscript(&mut self, index: u32, script: &Script) -> Result<&mut Self, Error> {
        unimplemented!()
    }

    fn add_input_derivation(&mut self, index: u32, fingerprint: Fingerprint, path: &DerivationPath) -> Result<&mut Self, Error> {
        unimplemented!()
    }

    fn add_output_script(&mut self, index: u32, script: &Script) -> Result<&mut Self, Error> {
        unimplemented!()
    }

    fn add_output_wscript(&mut self, index: u32, script: &Script) -> Result<&mut Self, Error> {
        unimplemented!()
    }

    fn add_output_derivation(&mut self, index: u32, fingerprint: Fingerprint, path: &DerivationPath) -> Result<&mut Self, Error> {
        unimplemented!()
    }
}
