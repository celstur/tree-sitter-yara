# tree-sitter-yara
Tree-sitter plugin for the Yara language.

This is a fork of the original [tree-sitter-yara](https://github.com/egibs/tree-sitter-yara) by [egibs](https://github.com/egibs), which lacks support for some (new) YARA rules features (as of September 2025).

## My additions:
> Features not listed here are either not implemented yet or they were already added by the first grammar author.

#### *Strings* section
- [x] support for **sequences of bytes as hex string alternatives**
- [x] support for **nibble-wise wild-cards in hex strings**
- [x] support for **the *not* operator ("~") in hex strings**
- [x] support for **jumps in hex strings**
- [x] support for **byte range after the *xor* string modifier**
- [x] support for **escape sequences in text strings**
- [x] support for **the *private* string modifier**
#### *Conditions* section
- [x] support for **string count in a specified range**
- [x] support for **string presence at an offset**
- [x] support for **string presence in a specified offset range**

#### General
- [ ] partial support for **hexadecimal integer literals where they are allowed**
---
### Testing
So far, the parser has been tested on the example rules from the [*Writing YARA rules*](https://yara.readthedocs.io/en/stable/writingrules.html) tutorial. I am planning to test it on larger subsets of rules after it is more developed.