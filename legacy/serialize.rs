// BP Core Library implementing LNP/BP specifications & standards related to
// bitcoin protocol
//
// Written in 2020-2022 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the Apache 2.0 License
// along with this software.
// If not, see <https://opensource.org/licenses/Apache-2.0>.

use std::io::{self, Read, Write};

use super::ScriptBytes;
use crate::LeafScript;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display("end of data reached while parsing with bitcoin consensus rules")]
pub struct NoData;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display("serialization overflow")]
pub struct TooLarge;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum DataError {
    #[from(NoData)]
    /// end of data reached while parsing with bitcoin consensus rules
    NoData,

    /// data left after complete deserialization of bitcoin structure
    ExcessiveData,
}

pub trait ConsensusRead: Read {
    fn read_u8(&mut self) -> Result<u8, io::Error>;
    fn read_u16(&mut self) -> Result<u16, io::Error>;
    fn read_u32(&mut self) -> Result<u32, io::Error>;
    fn read_u64(&mut self) -> Result<u64, io::Error>;
    fn read_var_int(&mut self) -> Result<u64, io::Error>;
}

pub trait ConsensusWrite: Write {
    fn write_u8(&mut self, val: u8) -> Result<(), io::Error>;
    fn write_u16(&mut self, val: u16) -> Result<(), io::Error>;
    fn write_u32(&mut self, val: u32) -> Result<(), io::Error>;
    fn write_u64(&mut self, val: u64) -> Result<(), io::Error>;
    fn write_var_int(&mut self, val: u64) -> Result<(), io::Error>;
}

/// Consensus data can't be larger than 4000000
pub type ConsensusIo<Io> = ConfinedIo<Io, 4_000_000>;

impl<R: Read> ConsensusRead for R {
    fn read_u8(&mut self) -> Result<u8, io::Error> {
        let mut val = [0; 1];
        self.read_exact(&mut val)?;
        Ok(val[0])
    }
    fn read_u16(&mut self) -> Result<u16, io::Error> {
        let mut val = [0; 2];
        self.read_exact(&mut val)?;
        Ok(u16::from_le_bytes(val))
    }
    fn read_u32(&mut self) -> Result<u32, io::Error> {
        let mut val = [0; 4];
        self.read_exact(&mut val)?;
        Ok(u32::from_le_bytes(val))
    }
    fn read_u64(&mut self) -> Result<u64, io::Error> {
        let mut val = [0; 8];
        self.read_exact(&mut val)?;
        Ok(u64::from_le_bytes(val))
    }

    fn read_var_int(&mut self) -> Result<u64, io::Error> {
        let n = self.read_u8()?;
        match n {
            0xFF => {
                let x = self.read_u64()?;
                if x < 0x100000000 {
                    Err(io::ErrorKind::InvalidInput.into())
                } else {
                    Ok(x)
                }
            }
            0xFE => {
                let x = self.read_u32()?;
                if x < 0x10000 {
                    Err(io::ErrorKind::InvalidInput.into())
                } else {
                    Ok(x as u64)
                }
            }
            0xFD => {
                let x = self.read_u16()?;
                if x < 0xFD {
                    Err(io::ErrorKind::InvalidInput.into())
                } else {
                    Ok(x as u64)
                }
            }
            n => Ok(n as u64),
        }
    }
}

impl<W: Write> ConsensusWrite for W {
    fn write_u8(&mut self, val: u8) -> Result<(), io::Error> {
        self.write_all(&[val])
    }

    fn write_u16(&mut self, val: u16) -> Result<(), io::Error> {
        self.write_all(&val.to_le_bytes())
    }

    fn write_u32(&mut self, val: u32) -> Result<(), io::Error> {
        self.write_all(&val.to_le_bytes())
    }

    fn write_u64(&mut self, val: u64) -> Result<(), io::Error> {
        self.write_all(&val.to_le_bytes())
    }

    fn write_var_int(&mut self, val: u64) -> Result<(), io::Error> {
        match val {
            0..=0xFC => {
                self.write_u8(val as u8)?;
            }
            0xFD..=0xFFFF => {
                self.write_u8(0xFD)?;
                self.write_u16(val as u16)?;
            }
            0x10000..=0xFFFFFFFF => {
                self.write_u8(0xFE)?;
                self.write_u32(val as u32)?;
            }
            _ => {
                self.write_u8(0xFF)?;
                self.write_u64(val as u64)?;
            }
        }
        Ok(())
    }
}

pub trait ConsensusDecode: Sized {
    fn consensus_decode(reader: impl ConsensusRead) -> Result<Self, io::Error>;
}

pub trait ConsensusEncode {
    fn consensus_encode(
        &self,
        writer: impl ConsensusWrite,
    ) -> Result<(), io::Error>;
}

impl ConsensusEncode for ScriptBytes {
    fn consensus_encode(
        &self,
        mut writer: impl ConsensusWrite,
    ) -> Result<(), io::Error> {
        writer.write_var_int(self.len() as u64)?;
        writer.write_all(self.as_ref())
    }
}

impl ConsensusEncode for LeafScript {
    fn consensus_encode(
        &self,
        mut writer: impl ConsensusWrite,
    ) -> Result<(), io::Error> {
        writer.write_u8(self.version.to_consensus())?;
        self.script.consensus_encode(writer)
    }
}
