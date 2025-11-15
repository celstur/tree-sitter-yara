# tree-sitter-yara
Tree-sitter plugin for the Yara language.

This is a fork of the original [tree-sitter-yara](https://github.com/egibs/tree-sitter-yara) by [egibs](https://github.com/egibs), which lacks support for some (new) YARA rules features (as of September 2025).

### My additions (fixing the grammar):
- [x] support for **sequences of bytes as hex string alternatives**
- [x] support for **nibble-wise wild-cards**
- [x] support for **the not operator ("~") in hex strings**
- [x] support for **jumps in hex strings**
- [ ] ...
