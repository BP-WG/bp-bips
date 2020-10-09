[![crates.io](https://meritbadge.herokuapp.com/psbt)](https://crates.io/crates/psbt)
[![Docs](https://docs.rs/psbt/badge.svg)](https://docs.rs/psbt)
![Build](https://github.com/LNP-BP/rust-psbt/workflows/Build/badge.svg)
![Tests](https://github.com/LNP-BP/rust-psbt/workflows/Tests/badge.svg)
![Lints](https://github.com/LNP-BP/rust-psbt/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/LNP-BP/rust-psbt/branch/master/graph/badge.svg)](https://codecov.io/gh/LNP-BP/rust-psbt)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# Rust PSBT Library (partially-signed bitcoin transactions)

Rust crates implementing partially-signed bitcoin transactions spec (BIP-174), 
as a library and small command-line tool, supporting rustc 1.29.0

[Documentation](https://docs.rs/psbt/)

Supports (or should support)

* De/serialization of PSBT and it's internal data structures
* PSBT creation, manipulation, merging and finalization

# Contributing
Contributions are generally welcome. If you intend to make larger changes please
discuss them in an issue before PRing them to avoid duplicate work and
architectural mismatches. If you have any questions or ideas you want to discuss
please join us in [#lnp-bp](http://webchat.freenode.net/?channels=%23lnp-bp) on
freenode.

## Minimum Supported Rust Version (MSRV)
This library should always compile with any combination of features on 
**Rust 1.41.1**.

## Installing Rust
Rust can be installed using your package manager of choice or
[rustup.rs](https://rustup.rs). The former way is considered more secure since
it typically doesn't involve trust in the CA system. But you should be aware
that the version of Rust shipped by your distribution might be out of date.

## Building
The library can be built and tested using [`cargo`](https://github.com/rust-lang/cargo/):

```
git clone git@github.com:LNP-BP/rust-psbt.git
cd rust-psbt
cargo build
```

You can run tests with:

```
cargo test
```

Please refer to the 
[`cargo` documentation](https://doc.rust-lang.org/stable/cargo/) for more 
detailed instructions. 

## Pull Requests
Every PR needs at least two reviews to get merged. During the review phase
maintainers and contributors are likely to leave comments and request changes.
Please try to address them, otherwise your PR might get closed without merging
after a longer time of inactivity..


# Release Notes

See [CHANGELOG.md](CHANGELOG.md).


# Licensing

The code in this project is licensed under the [Apache License 2.0](LICENSE).
