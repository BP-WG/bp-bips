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

use bc::ScriptPubkey;

use crate::addr::Address;
use crate::keys::DescrKey;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum DerivatorError {
    /// derivation path length exceeded maximum 255 elements.
    TooDeep,

    /// attempt to derive key using variable index at unknown position {0}.
    UnknownPosition(u8),
}

pub trait TerminalDerivator {
    fn index_at(&self, pos: u8) -> Result<NormIndex, DerivatorError>;
}

pub trait ConcretePubkey {}
pub trait DerivePubkey {
    type ConcreteKey: DescrKey;
    fn derive_pattern_len(&self) -> u8;
    fn derive_pubkey(
        &self,
        derivator: &impl TerminalDerivator,
    ) -> Result<Self::ConcreteKey, DerivatorError>;
}

pub trait Descriptor<Key> {
    fn derive_script_pubkey(
        &self,
        derivator: &impl TerminalDerivator,
    ) -> Result<ScriptPubkey, DerivatorError>
    where
        Key: DerivePubkey;

    fn script_pubkey(&self) -> ScriptPubkey
    where Self::Key: ConcretePubkey;

    fn derive_address(
        &self,
        derivator: &impl TerminalDerivator,
    ) -> Result<ScriptPubkey, DerivatorError>
    where
        Key: DerivePubkey,
    {
        self.derive_script_pubkey(derivator).map(Address::into)
    }

    fn address(&self) -> Address
    where Self::Key: ConcretePubkey {
        self.script_pubkey().into()
    }
}
