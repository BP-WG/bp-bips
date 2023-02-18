use core2::io::Cursor;

use super::Psbt;

pub enum DecodeError {}

pub trait Encoding {
    fn encode(&self, buf: &mut Vec<u8>);
    fn decode(cursor: &mut Cursor<&[u8]>) -> Result<Self, DecodeError> where Self: Sized;
}

impl Encoding for Psbt {
    fn encode(&self, buf: &mut Vec<u8>) {
        todo!()
    }

    fn decode(cursor: &mut Cursor<&[u8]>) -> Result<Self, DecodeError> where Self: Sized {
        todo!()
    }
}

impl Psbt {
    pub fn from_raw(data: &[u8]) -> Result<Self, DecodeError> {
        let mut cursor = Cursor::new(data);
        Self::decode(&mut cursor)
    }

    pub fn to_raw(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }
}
