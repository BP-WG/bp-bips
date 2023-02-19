# PSBT crate

Implements both v0 (BIP-174) and v2 (BIP-370) versions of PSBT specification.

Minimal-dependency, no-std, 100% standard compliant, with no non-standard 
assumptions. 

Differs PSBT from `bitcoin` crate in the following ways:
- supports PSBT v2;
- preserves the original content of PSBT (i.e. serialization of PSBT with no 
modifications always strictly match the original serialization);
- simplifies workflow for managing custom keys.
