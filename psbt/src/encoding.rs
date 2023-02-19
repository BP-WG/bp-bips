// Partially signed bitcoin transaction library (BIP174, BIP370, BIP371)
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2020-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2020-2023 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2020-2023 Dr Maxim Orlovsky. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
