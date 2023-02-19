// Bitcoin descriptors implementation
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

use crate::keys::AnyKey;

pub enum DeriveError {
    HardenedIndex,
    PatternMismatch,
}

pub trait ConcretePubkey: AnyKey {}
pub trait DerivePubkey: AnyKey {
    type ConcreteKey: AnyKey;
    fn derive_pattern_len(&self) -> u8;
    fn derive_pubkey(
        &self,
        pattern: impl IntoIterator<Item = NormIndex>,
    ) -> Result<Self::ConcreteKey, DeriveError>;
}

pub trait Descriptor {
    type Key: AnyKey;

    fn derive_script_pubkey(
        &self,
        pattern: impl IntoIterator<Item = NormIndex>,
    ) -> Result<ScriptPubkey, DeriveError>
    where
        Self::Key: DerivePubkey;

    fn script_pubkey(&self) -> ScriptPubkey
    where Self::Key: ConcretePubkey;

    fn derive_address(
        &self,
        pattern: impl IntoIterator<Item = NormIndex>,
    ) -> Result<ScriptPubkey, DeriveError>
    where
        Self::Key: DerivePubkey,
    {
        self.derive_script_pubkey(pattern).map(Address::into)
    }

    fn address(&self) -> Address
    where Self::Key: ConcretePubkey {
        self.script_pubkey().into()
    }
}
