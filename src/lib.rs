//! Zero-dependency no-std 100% standard-compliant PSBT v0 and v2 implementation.

pub trait PsbtKeyType {}

pub enum InKey {}
impl PsbtKeyType for InKey {}

pub enum OutKey {}
impl PsbtKeyType for OutKey {}

pub enum GlobalKey {}
impl PsbtKeyType for GlobalKey {}

pub struct UnknownKey(u64);
impl PsbtKeyType for UnknownKey {}

pub struct Psbt {
    global: KeyMap<GlobalKey>,
    inputs: Vec<KeyMap<InKey>>,
    outputs: Vec<KeyMap<OutKey>>,
}

pub struct KeyMap<T: PsbtKeyType>(Vec<KeyPair<T>>);

pub struct KeyPair<T: PsbtKeyType> {
    pub key: Key<T>,
    pub value: Vec<u8>
}

pub enum Key<T: PsbtKeyType> {
    Known(CommonKey<T>),
    Unknown(CommonKey<UnknownKey>),
    Proprietary(ProprietaryKey),
}

pub struct CommonKey<T: PsbtKeyType> {
    pub key_type: T,
    pub key_data: Vec<u8>,
}

pub struct ProprietaryKey {
    pub identifier: String,
    pub subtype: u64,
    pub key_data: Vec<u8>,
}

pub enum KeyType {
}
