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

//! Standard expressions used by descriptors

use crate::keys::{AnyKey, CompressedKey, XonlyKey};

pub struct KeyOrigin {
    pub master_fp: Fingerprint,
    pub derivation: DerivationPath,
}

pub struct KeyExpr<K: AnyKey> {
    pub origin: Option<KeyOrigin>,
    pub key: K,
}

pub trait ScriptExpr<K: AnyKey> {}
pub trait WScriptExpr<K: CompressedKey> {}
pub trait TapScriptExpr<K: XonlyKey>: ScriptExpr<K> {}

pub enum NodeExpr<S: TapScriptExpr<K>, K: XonlyKey> {
    TapScript(S),
    NodeHash(TapNodeHash),
    Tree(Box<TreeExpr<S, K>>),
}

pub struct TreeExpr<S: TapScriptExpr<K>, K: XonlyKey> {
    pub first: NodeExpr<S, K>,
    pub second: Option<NodeExpr<S, K>>,
}
