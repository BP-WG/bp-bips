# BIPs wallet-level standards implementation

![Build](https://github.com/BP-WG/bp-bips/workflows/Build/badge.svg)
![Tests](https://github.com/BP-WG/bp-bips/workflows/Tests/badge.svg)
![Lints](https://github.com/BP-WG/bp-bips/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/BP-WG/bp-bips/branch/master/graph/badge.svg)](https://codecov.io/gh/BP-WG/bp-bips)

[![crates.io](https://img.shields.io/crates/v/bp-bips)](https://crates.io/crates/bp-bips)
[![Docs](https://docs.rs/bp-bips/badge.svg)](https://docs.rs/bp-bips)
[![Apache-2 licensed](https://img.shields.io/crates/l/bp-bips)](./LICENSE)

This repository provides a set of rust crates for implementing wallet-specific 
bitcoin standards (BIPs).

The set of libraries supports addresses, hierarchical bitcoin derivation 
standards, partially signed bitcoin transactions and bitcoin descriptors.


## Documentation

Detailed developer & API documentation for all libraries can be accessed at:
- <https://docs.rs/psbt/>
- <https://docs.rs/descriptors/>
- <https://docs.rs/bitcoin_hd/>


## Usage

The repository contains rust libraries (crates) for building standard-compliant
bitcoin applications.

### Use library in other projects

To use libraries, you just need latest version of libraries, published to
[crates.io](https://crates.io) into `[dependencies]` section of your project
`Cargo.toml`. Here is the full list of available libraries from this repository:

```toml
psbt = "0.10" # Partially-signed bitcoin transactions
descriptors = "0.10" # Descriptor-based wallet applications
bitcoin_hd = "0.10" # Hierarchically-derived wallet applications
```


## Contributing

Contribution guidelines can be found in [CONTRIBUTING](CONTRIBUTING.md)


## More information

### MSRV

This library requires minimum rust compiler version (MSRV) 1.60.0.

### Policy on altcoins

Altcoins and "blockchains" other than Bitcoin blockchain/Bitcoin protocols are
not supported and not planned to be supported; pull requests targeting them will
be declined.

### Licensing

The libraries are distributed on the terms of Apache 2.0 opensource license.
See [LICENCE](LICENSE) file for the license details.
