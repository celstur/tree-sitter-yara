# tree-sitter-yara
Tree-sitter plugin for the Yara language.

This is a fork of the original [tree-sitter-yara](https://github.com/egibs/tree-sitter-yara), by [egibs](https://github.com/egibs), which lacks support for some (new) YARA rules features (as of October 2025).

## My additions:
> Features not listed here are either not implemented yet or they have already been done by the first grammar author.
### *Strings* section
- [x] support for **sequences of bytes as hex string alternatives**
- [x] support for **nibble-wise wild-cards in hex strings**
- [x] support for **the *not* (`~`) operator in hex strings**
- [x] support for **jumps in hex strings**
- [x] support for **byte range after the `xor` string modifier**
- [x] support for **escape sequences in text strings**
- [x] support for **the `private` string modifier**
### *Conditions* section
- [x] support for **string count in a specified range**
- [x] support for **string presence at an offset**
- [x] support for **string presence in a specified offset range**
- [x] support for **variables from modules**
- [x] removed support for **deprecated `entrypoint` keyword**
- [x] support for **integer-reading functions**
- [x] support for **module functions**
- [x] support for **sets of strings**
- [x] support for **`of` and `for...of` expressions**
- [x] support for **iterating over *ranges*, *enumerations*, *arrays* and *dictionaries* with a `for <vars> in <iterable> : ...` expression**

### Semantics
- [ ] support for **any numeric expression where it is allowed**
- [ ] support for **any boolean expression where it is allowed**
- [x] partial support for **correct semantic rules for the integer `0` or `[0]+` in things like *indexes* or *ranges***
- [ ] allow **`#`, `$`, `@` and `!` to be used without *identifiers* only in the correct places**
- [ ] support for **bitwise operators**
---
### Testing
So far, the parser has been tested on the example rules from the [*Writing YARA rules*](https://yara.readthedocs.io/en/stable/writingrules.html) tutorial. I am planning to test it on larger subsets of rules after it is more developed.