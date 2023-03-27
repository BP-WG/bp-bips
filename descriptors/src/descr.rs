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

use amplify::confinement::TinyVec;

use crate::addr::Address;
use crate::expr::{KeyExpr, ScriptExpr, TapScriptExpr, TapretExpr, TreeExpr, WScriptExpr};
use crate::keys::{CompressedKey, DescrKey, XonlyKey};

pub struct Pk<K>(KeyExpr<K>);

pub struct Sh<K, S: ScriptExpr<K>>(S);

pub struct Wpk<K: CompressedKey>(KeyExpr<K>);

pub struct Wsh<K: CompressedKey, S: ScriptExpr<K>>(S);

pub struct Tr<K: XonlyKey, S: TapScriptExpr<K>>(KeyExpr<K>, Option<TreeExpr<S, K>>, TapretExpr);

pub struct Multi<K>(u8, TinyVec<K>);
impl<K> ScriptExpr<K> for Multi<K> {}
impl<K: CompressedKey> WScriptExpr<K> for Multi<K> {}

pub struct SortedMulti<K>(u8, TinyVec<K>);
impl<K> ScriptExpr<K> for SortedMulti<K> {}
impl<K: CompressedKey> WScriptExpr<K> for SortedMulti<K> {}

pub struct Combo<K: DescrKey>(K);

pub struct Raw(Vec<u8>);

pub struct Addr(Address);
