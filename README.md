[![Status](https://travis-ci.org/rust-bitcoin/rust-psbt.png?branch=master)](https://travis-ci.org/rust-bitcoin/rust-psbt)
[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

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
please join us in
[#rust-bitcoin](http://webchat.freenode.net/?channels=%23rust-bitcoin) on
freenode.

## Minimum Supported Rust Version (MSRV)
This library should always compile with any combination of features on **Rust 1.29**.

## Installing Rust
Rust can be installed using your package manager of choice or
[rustup.rs](https://rustup.rs). The former way is considered more secure since
it typically doesn't involve trust in the CA system. But you should be aware
that the version of Rust shipped by your distribution might be out of date.
Generally this isn't a problem for `rust-bitcoin` since we support much older
versions (>=1.22) than the current stable one.

## Building
The library can be built and tested using [`cargo`](https://github.com/rust-lang/cargo/):

```
git clone git@github.com:rust-bitcoin/rust-psbt.git
cd rust-psbt
cargo build
```

You can run tests with:

```
cargo test
```

Please refer to the [`cargo` documentation](https://doc.rust-lang.org/stable/cargo/) for more detailed instructions. 

## Pull Requests
Every PR needs at least two reviews to get merged. During the review phase
maintainers and contributors are likely to leave comments and request changes.
Please try to address them, otherwise your PR might get closed without merging
after a longer time of inactivity. If your PR isn't ready for review yet please
mark it by prefixing the title with `WIP: `.


# Release Notes

See [CHANGELOG.md](CHANGELOG.md).


# Licensing

The code in this project is licensed under the [Creative Commons CC0 1.0
Universal license](LICENSE).
