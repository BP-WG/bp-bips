// Rust PSBT Library
// Written by
//   Dr Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

mod creator;
mod updater;
mod signer;
mod combiner;
mod finalizer;
mod extractor;

pub use self::creator::Creator;
pub use self::updater::Updater;
pub use self::signer::Signer;
pub use self::combiner::Combiner;
pub use self::finalizer::Finalizer;
pub use self::extractor::Extractor;

use std::fmt::{self, Display, Debug, Formatter};

use PartiallySignedTransaction;

/// PSBT-related roles according to
/// [BIP-174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
/// and https://github.com/bitcoin/bitcoin/blob/master/src/psbt.h#L559
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
// Tracking PR https://github.com/bitcoin/bips/pull/989
pub enum Role {
    Creator,
    Updater,
    Signer,
    Combiner,
    Finalizer,
    Extractor,
}

impl Default for Role {
    fn default() -> Self {
        Role::Creator
    }
}

impl Display for Role {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        (self as &Debug).fmt(f)
    }
}

impl Role {
    pub fn init() -> Role {
        Role::default()
    }

    pub fn next(&self) -> Option<Role> {
        match self {
            Role::Creator => Some(Role::Updater),
            Role::Updater => Some(Role::Signer),
            Role::Signer => Some(Role::Combiner),
            Role::Combiner => Some(Role::Finalizer),
            Role::Finalizer => Some(Role::Extractor),
            Role::Extractor => None
        }
    }
}

impl PartiallySignedTransaction {
    // Must be kept in accordance with
    // https://github.com/bitcoin/bitcoin/blob/master/src/node/psbt.cpp#L15
    pub fn prev_role(&self) -> Role {
        match self {
            me if me.has_final_info() => Role::Finalizer,
            me if me.has_all_signatures() => Role::Combiner,
            me if me.has_partial_signatures() => Role::Signer,
            me if me.has_sign_info() => Role::Updater,
            _ => Role::Creator,
        }
    }

    pub fn next_role(&self) -> Option<Role> {
        self.prev_role().next()
    }
}
