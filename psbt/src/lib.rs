//! Zero-dependency no-std 100% standard-compliant PSBT v0 and v2 implementation.

mod encoding;

pub use encoding::{DecodeError, Encoding};

use core::marker::PhantomData;

pub trait KnownPair {}

pub enum InPair {}
impl KnownPair for InPair {}

pub enum OutPair {}
impl KnownPair for OutPair {}

pub enum GlobalPair {
    UnsignedTx(Tx),
    Xpub(XpubDerivation),
    TxVersion(u32 /* TxVer must become u32-representable */),
    InputCount(u64),
    OutputCount(u64),
    TxModifiable(u8),
    Version(u32),
}
impl KnownPair for GlobalPair {}

pub struct UnknownPair<T: KnownPair> {
    key_type: u64,
    key_data: Vec<u8>,
    value: Vec<u8>,
    _map_type: PhantomData<T>,
}

pub struct ProprietaryPair {
    pub identifier: String,
    pub subkey_type: u64,
    pub subkey_data: Vec<u8>,
    pub value: Vec<u8>
}

pub struct Psbt {
    global: KeyMap<GlobalPair>,
    inputs: Vec<KeyMap<InPair>>,
    outputs: Vec<KeyMap<OutPair>>,
}

pub struct KeyMap<T: KnownPair>(Vec<KeyPair<T>>);

pub enum KeyPair<T: KnownPair> {
    Known(T),
    Unknown(UnknownPair<T>),
    Proprietary(ProprietaryPair),
}
