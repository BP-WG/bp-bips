# PSBT crate

![Build](https://github.com/BP-WG/bp-bips/workflows/Build/badge.svg)
![Tests](https://github.com/BP-WG/bp-bips/workflows/Tests/badge.svg)
![Lints](https://github.com/BP-WG/bp-bips/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/BP-WG/bp-bips/branch/master/graph/badge.svg)](https://codecov.io/gh/BP-WG/bp-bips)

[![crates.io](https://img.shields.io/crates/v/psbt)](https://crates.io/crates/psbt)
[![Docs](https://docs.rs/psbt/badge.svg)](https://docs.rs/psbt)
[![Apache-2 licensed](https://img.shields.io/crates/l/psbt)](./LICENSE)

Implements both v0 (BIP-174) and v2 (BIP-370) versions of PSBT specification.

Minimal-dependency, no-std, 100% standard compliant, with no non-standard 
assumptions. 

Differs PSBT from `bitcoin` crate in the following ways:
- supports PSBT v2;
- preserves the original content of PSBT (i.e. serialization of PSBT with no 
modifications always strictly match the original serialization);
- simplifies workflow for managing custom keys.
