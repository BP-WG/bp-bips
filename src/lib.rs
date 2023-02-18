//! Zero-dependency no-std 100% standard-compliant PSBT v0 and v2 implementation.

pub struct Psbt {
    global: GlobalMap,
    inputs: Vec<InputMap>,
    outputs: Vec<OutputMap>,
}

pub struct GlobalMap(Vec<KeyPair>);

pub struct InputMap(Vec<KeyPair>);

pub struct OutputMap(Vec<KeyPair>);

pub struct KeyPair {
    pub key: Key,
    pub value: Vec<u8>
}

pub enum Key {
    Standard(StandardKey),
    Proprietary(ProprietaryKey),
}

pub struct StandardKey {
    pub key_type: u64,
    pub key_data: Vec<u8>,
}

pub struct ProprietaryKey {
    pub identifier: String,
    pub subtype: u64,
    pub key_data: Vec<u8>,
}
