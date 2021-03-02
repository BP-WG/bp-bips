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

extern crate serde_crate as serde;

use clap::{AppSettings, Clap};
use serde::Serialize;
use std::fmt::{self, Debug, Display, Formatter};
use std::io::{self, Read};
use std::str::FromStr;

use bech32::{FromBase32, ToBase32};
use bitcoin::consensus::{deserialize, serialize, Decodable, Encodable};
use bitcoin::hashes::hex::{self, FromHex, ToHex};

use psbt::v1::Psbt;

#[derive(Clap, Clone, Debug)]
#[clap(
    name = "psbt",
    bin_name = "psbt",
    author,
    version,
    about = "Command-line tool for working with partially-signed bitcoin transactions",
    setting = AppSettings::ColoredHelp,
)]
pub struct Opts {
    /// Command to execute
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Clap, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[clap(setting = AppSettings::ColoredHelp)]
pub enum Command {
    /// Converting between different representations of PSBT data
    Convert {
        /// PSBT data; if none are given reads from STDIN
        psbt: Option<String>,

        /// Formatting of the input PSBT data
        #[clap(short, long, default_value = "base64")]
        input: Format,

        /// Formatting for the output PSBT data
        #[clap(short, long, default_value = "yaml")]
        output: Format,
    },

    /// Signs PSBT. For each unsigned input asks for corresponding master
    /// extended private key
    Sign {
        /// PSBT input data; if none are given reads from STDIN
        input: Option<String>,

        /// Resulting PSBT with (partial) signatures;
        /// if none are given writes to STDOUT
        output: Option<String>,

        /// Formatting of the PSBT data
        #[clap(short, long, default_value = "base64")]
        format: Format,
    },
}

/// Formatting of the data
#[derive(Clap, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum Format {
    /// Format according to the rust debug rules
    Debug,

    /// Format using Bech32 representation
    Bech32,

    /// Format using BIP-174 Base64 encoding
    Base64,

    /// Format as YAML
    Yaml,

    /// Format as JSON
    Json,

    /// Format according to the strict encoding rules
    Hexadecimal,

    /// Format as a rust array (using hexadecimal byte values)
    Rust,

    /// Produce binary (raw) output according to BIP-174 serialization rules
    Bip174,
}

impl Display for Format {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Format::Debug => f.write_str("debug"),
            Format::Base64 => f.write_str("base64"),
            Format::Bech32 => f.write_str("bech32"),
            Format::Yaml => f.write_str("yaml"),
            Format::Json => f.write_str("json"),
            Format::Hexadecimal => f.write_str("hex"),
            Format::Rust => f.write_str("rust"),
            Format::Bip174 => f.write_str("bip174"),
        }
    }
}

impl FromStr for Format {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.trim().to_lowercase().as_str() {
            "debug" => Format::Debug,
            "base64" => Format::Base64,
            "bech32" => Format::Bech32,
            "yaml" => Format::Yaml,
            "json" => Format::Json,
            "hex" => Format::Hexadecimal,
            "raw" | "bip174" => Format::Bip174,
            "rust" => Format::Rust,
            other => Err(format!("Unknown format: {}", other))?,
        })
    }
}

fn input_read<T>(data: Option<String>, format: Format) -> Result<T, String>
where
    T: Decodable + for<'de> serde::Deserialize<'de>,
{
    let data = data
        .map(|d| d.as_bytes().to_vec())
        .ok_or(String::default())
        .or_else(|_| -> Result<Vec<u8>, String> {
            let mut buf = Vec::new();
            io::stdin()
                .read_to_end(&mut buf)
                .as_ref()
                .map_err(io::Error::to_string)?;
            Ok(buf)
        })?;
    Ok(match format {
        Format::Bech32 => {
            let (hrp, data) = bech32::decode(&String::from_utf8_lossy(&data))
                .map_err(|err| err.to_string())?;
            let data =
                Vec::<u8>::from_base32(&data).map_err(|err| err.to_string())?;
            if hrp.to_lowercase() != "psbt" {
                return Err(
                    "Wrong bech32 PSBT data prefix; must be `psbt1...`"
                        .to_owned(),
                );
            }
            deserialize(&data).map_err(|err| err.to_string())?
        }
        Format::Base64 => deserialize(
            &base64::decode(&data)
                .map_err(|err| format!("Incorrect Base64 encoding: {}", err))?,
        )
        .map_err(|err| format!("Wrong PSBT data: {}", err))?,
        Format::Yaml => serde_yaml::from_str(&String::from_utf8_lossy(&data))
            .map_err(|err| err.to_string())?,
        Format::Json => serde_json::from_str(&String::from_utf8_lossy(&data))
            .map_err(|err| err.to_string())?,
        Format::Hexadecimal => deserialize(
            Vec::<u8>::from_hex(&String::from_utf8_lossy(&data))
                .as_ref()
                .map_err(hex::Error::to_string)?,
        )
        .map_err(|err| format!("Wrong PSBT data: {}", err))?,
        Format::Bip174 => deserialize(&data)
            .map_err(|err| format!("Wrong PSBT data: {}", err))?,
        _ => Err(format!("Can't read data from {} format", format))?,
    })
}

fn output_write<T>(
    mut f: impl io::Write,
    data: T,
    format: Format,
) -> Result<(), String>
where
    T: Debug + Serialize + Encodable,
{
    match format {
        Format::Debug => write!(f, "{:#?}", data),
        Format::Bech32 => write!(
            f,
            "{}",
            bech32::encode("psbt", serialize(&data).to_base32())
                .expect("embedded bech32 error")
        ),
        Format::Base64 => write!(f, "{}", base64::encode(&serialize(&data))),
        Format::Yaml => write!(
            f,
            "{}",
            serde_yaml::to_string(&data)
                .as_ref()
                .map_err(serde_yaml::Error::to_string)?
        ),
        Format::Json => write!(
            f,
            "{}",
            serde_json::to_string(&data)
                .as_ref()
                .map_err(serde_json::Error::to_string)?
        ),
        Format::Hexadecimal => write!(f, "{}", serialize(&data).to_hex()),
        Format::Rust => write!(f, "{:#04X?}", serialize(&data)),
        Format::Bip174 => data.consensus_encode(f).map(|_| ()),
    }
    .as_ref()
    .map_err(io::Error::to_string)?;
    Ok(())
}

fn main() -> Result<(), String> {
    let opts = Opts::parse();

    match opts.command {
        Command::Convert {
            psbt,
            input,
            output,
        } => {
            let psbt: Psbt = input_read(psbt, input)?;
            output_write(io::stdout(), psbt, output)?;
        }
        Command::Sign {
            input,
            output,
            format,
        } => unimplemented!(),
    }

    Ok(())
}
