//! Zero-dependency no-std 100% standard-compliant PSBT v0 and v2 implementation.

use core::marker::PhantomData;

pub trait KnownKey {}

pub enum InKey {}
impl KnownKey for InKey {}

pub enum OutKey {}
impl KnownKey for OutKey {}

pub enum GlobalKey {}
impl KnownKey for GlobalKey {}

pub struct UnknownKey<T: KnownKey>(u64, PhantomData<T>);

pub struct ProprietaryKey {
    pub identifier: String,
    pub subtype: u64,
}
impl KnownKey for ProprietaryKey {}

pub struct Psbt {
    global: KeyMap<GlobalKey>,
    inputs: Vec<KeyMap<InKey>>,
    outputs: Vec<KeyMap<OutKey>>,
}

pub struct KeyMap<T: KnownKey>(Vec<KeyPair<T>>);

pub struct KeyPair<T: KnownKey> {
    pub key_type: KeyType<T>,
    pub key_data: Vec<u8>,
    pub value: Vec<u8>
}

pub enum KeyType<T: KnownKey> {
    Known(T),
    Unknown(UnknownKey<T>),
    Proprietary(ProprietaryKey),
}
