# PSBT crate

Implements both v0 (BIP-174) and v2 (BIP-370) versions of PSBT specification.

Minimal-dependency, 100% standard compliant, with no non-standard assumptions.
Inlone PSBT from `bitcoin` crate the library preserves the original content of 
PSBT (i.e. serialization of PSBT with no modifications always strictly match the
original serialization). It also has a simplified workflow for managing custom
keys.
