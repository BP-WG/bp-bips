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

//! Per-input typed map from PSBT

/*
#[derive(TypedMap)]
pub enum InputTypes {
    #[typed_key(0x00, data = Transaction)]
    NonWitnessUtxo,

    #[typed_key(0x01, data = Transaction)]
    WitnessUtxo,

    #[typed_key(0x02, subkey = PublicKey, data = Signature)]
    PartialSig,

    #[typed_key(0x03, data = SigHashType)]
    SigHashType,

    #[typed_key(0x04, data = Script)]
    RedeemScript,

    #[typed_key(0x05, data = Vec<Vec<u8>>)]
    WitnessScript,

    #[typed_key(0x06, subkey = PublicKey, data = KeySource)]
    Bip32Derivation,

    #[typed_key(0x07, data = Script)]
    FinalScriptSig,

    #[typed_key(0x08, data = Vec<Vec<u8>>)]
    FinalScriptWitness,

    #[typed_key(0x09, subkey = ripemd160::Hash, data = Vec<u8>)]
    RipemdPreimages,
}
*/
