/**
 * @file Tree-sitter plugin for the Yara language.
 * @author egibs <evan@egibs.xyz>, @author celstur
 * @license MIT
 */

/// <reference types="tree-sitter-cli/dsl" />
// @ts-check

const PREC = {
  primary: 13,
  unary: 12,
  multiplicative: 11,
  additive: 10,
  bit_shift: 9,
  bit_and: 8,
  bit_xor: 7,
  bit_or: 6,
  comparative: 5,
  equality: 4,
  not_defined: 3,
  and: 2,
  or: 1,
};

module.exports = grammar({
  name: "yara",

  extras: ($) => [$.comment, /[\s\f\uFEFF\u2060\u200B]|\r?\n/],

  word: ($) => $.identifier,

  conflicts: ($) => [
    [$._expression, $._numeric_expression],
    [$._expression, $.parenthesized_numeric_expression]
  ],

  rules: {
    source_file: ($) =>
      prec.right(
        0,
        repeat(
          choice($.import_statement, $.include_statement, $.rule_definition),
        ),
      ),

    // Token definitions
    _equal: (_) => "=",
    _colon: (_) => ":",
    _lbrace: (_) => "{",
    _rbrace: (_) => "}",
    _lbrack: (_) => "[",
    _rbrack: (_) => "]",
    _lparen: (_) => "(",
    _rparen: (_) => ")",
    _dollar: (_) => "$",
    _hash: (_) => "#",
    _at: (_) => "@",
    _range: (_) => "-",
    _range2: (_) => "..",
    _question: (_) => "?",
    _pipe: (_) => "|",
    _comma: (_) => ",",
    _bang: (_) => "!",
    _slash: (_) => "/",
    _quote: (_) => '"',
    _squote: (_) => "'",

    import_statement: ($) => seq("import", $.double_quoted_string),

    include_statement: ($) => seq("include", $.double_quoted_string),

    rule_definition: ($) =>
      seq(
        optional("private"),
        optional("global"),
        "rule",
        field("name", $.identifier),
        optional($.tag_list),
        field("body", $.rule_body),
      ),

    tag_list: ($) =>
      seq($._colon, $.identifier, repeat(alias($.identifier, $.tag))),

    rule_body: ($) =>
      prec.right(
        seq(
          $._lbrace,
          optional($.meta_section),
          optional($.strings_section),
          $.condition_section,
          $._rbrace,
        ),
      ),

    meta_section: ($) => seq("meta", $._colon, repeat1($.meta_definition)),

    meta_definition: ($) =>
      seq(
        field("key", $.identifier),
        $._equal,
        field(
          "value",
          choice($.string_literal, $.integer_zero, $.integer_decimal_positive, $.boolean_literal),
        ),
      ),

    strings_section: ($) =>
      seq("strings", $._colon, repeat1($.string_definition)),

    string_definition: ($) =>
      seq(
        field("name", $.string_identifier),
        $._equal,
        field("value", choice($.text_string, $.hex_string, $.regex_string)),
        optional($.string_modifiers),
      ),

    string_identifier: (_) => token(/\$[a-zA-Z0-9_]*/),

    text_string: ($) =>
      token(choice(
        seq(
          '"',
          repeat(choice(seq('\\', choice(/["\\rtn]/, /x[0-9A-Fa-f]{2}/)), /[^"\\]+/)),
          '"'
        ),
        seq(
          "'",
          repeat(choice(seq('\\', choice(/["\\rtn]/, /x[0-9A-Fa-f]{2}/)), /[^"\\]+/)),
          "'"
        ))),

    hex_string: ($) =>
      seq(
        $._lbrace,
        choice($.hex_seq, $.hex_alternative),
        repeat(
          seq(choice(
            choice($.hex_seq, $.hex_alternative),
            seq($.hex_jump, choice($.hex_seq, $.hex_alternative))
          ))
        ),
        $._rbrace
      ),
    hex_seq: (_) => token(/(?:~?[0-9A-Fa-f?]{2})(?:\s*~?[0-9A-Fa-f?]{2})*/),
    hex_jump: ($) =>
      seq(
        $._lbrack,
        choice(
          seq(
            optional(choice($.integer_decimal_positive, $.integer_zero)),
            $._range,
            optional(choice($.integer_decimal_positive, $.integer_zero))
          ),
          $.integer_decimal_positive,
          $.integer_zero
        ),
        $._rbrack
      ),
    hex_alternative: ($) =>
      seq($._lparen, sep1($.hex_seq, $._pipe), $._rparen),

    regex_string: ($) =>
      prec.right(
        1,
        seq(
          $.regular_expression,
          optional($.string_modifiers),
        ),
      ),
    regular_expression: ($) =>
      seq(
        "/",
        repeat1(choice(token.immediate(/[^\/\\]+/), $.escape_sequence)),
        "/",
        optional(token(/i|s|is|si/))
      ),

    string_modifiers: ($) =>
      prec.left(
        1,
        repeat1(
          choice( // ---> no compatibility check
            "nocase",
            "ascii",
            "wide",
            "fullword",
            seq(
              "base64",
              optional(seq($._lparen, $.string_literal, $._rparen)),
            ),
            seq(
              "base64wide",
              optional(seq($._lparen, $.string_literal, $._rparen)),
            ),
            seq(
              "xor",
              optional(seq(
                $._lparen,
                $.hex_byte,
                optional(seq($._range, $.hex_byte)),
                $._rparen,
              )),
            ),
            "private",
          ),
        ),
      ),

    condition_section: ($) => seq("condition", $._colon, $._expression),

    _expression: ($) =>
      choice(
        $._numeric_expression,
        $.identifier,
        $.string_identifier,
        $.module_var_or_func,
        $.regular_expression,
        $.integer_decimal_positive,
        $.integer_zero,
        $.integer_hexadecimal,
        $.float_literal,
        $.boolean_literal,
        $.string_literal,
        $.string_at_offset,
        $.string_at_range, 
        $.filesize_keyword,
        $.read_function_call,
        $.for_of_expression,
        $.for_in_expression,
        $.of_expression,
        $.of_ruleset,
        $.parenthesized_expression,
        $.unary_expression,
        $.binary_expression,
      ),

    filesize_keyword: (_) => "filesize",

    size_unit: (_) => choice("KB", "MB", "GB"),

    integer_decimal_positive: ($) => seq(/[0]*[1-9][0-9]*/, optional($.size_unit)),
    integer_zero: ($) => seq(/[0]+/, optional($.size_unit)),
    integer_hexadecimal: (_) => /0x[0-9A-Fa-f]+/,
    float_literal: (_) => /[0-9]+\.[0-9]+/,
    hex_byte: (_) => /0x[0-9A-Fa-f]{2}|25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]/,
    boolean_literal: (_) => choice("true", "false"),

    string_literal: ($) =>
      choice($.double_quoted_string, $.single_quoted_string),

    string_expression: ($) =>
      choice($.string_literal, $.string_identifier, $.module_var_or_func, $.read_function_call),

    double_quoted_string: ($) =>
      seq(
        $._quote,
        repeat(choice(token.immediate(prec(1, /[^"\\]+/)), $.escape_sequence)),
        $._quote,
      ),
    single_quoted_string: ($) =>
      seq(
        $._squote,
        repeat(choice(token.immediate(prec(1, /[^'\\]+/)), $.escape_sequence)),
        $._squote,
      ),

    escape_sequence: (_) =>
      token.immediate(
        seq(
          "\\",
          choice(
            /[^xuU]/,
            /\d{2,3}/,
            /x[0-9a-fA-F]{2}/,
            /u[0-9a-fA-F]{4}/,
            /U[0-9a-fA-F]{8}/,
          ),
        ),
      ),

    string_count: ($) =>
      seq(
        token(/#[a-zA-Z_][a-zA-Z0-9_]*|#/),
        optional(seq("in", $.range))
      ),
    string_offset: ($) =>
      choice(
        seq(
          token(/@[a-zA-Z_][a-zA-Z0-9_]*/),
          optional(seq($._lbrack, $._numeric_expression, $._rbrack))
        ),
        token(/@/)
      ),
    string_at_offset: ($) =>
      prec.left(
        PREC.comparative,
        seq(
          choice($.string_identifier, $.of_expression),
          "at",
          $._numeric_expression
        )
      ),
    string_at_range: ($) =>
      prec.left(
        PREC.comparative,
        seq(
          choice($.string_identifier, $.of_expression),
          "in",
          $.range
        )
      ),
    string_length: ($) =>
      choice(
        seq(
          token(/![a-zA-Z_][a-zA-Z0-9_]*/),
          optional(seq($._lbrack, $._numeric_expression, $._rbrack))
        ),
        token(/!/)
      ),

    read_function_name: (_) => choice(
      "int8", "int16", "int32",
      "uint8", "uint16", "uint32",
      "int8be", "int16be", "int32be",
      "uint8be", "uint16be", "uint32be",
    ),
    read_function_call: ($) => seq($.read_function_name, $._lparen, $._numeric_expression, $._rparen),

    for_of_expression: ($) =>
      seq(
        "for",
        $.of_expression,
        $._colon,
        $.parenthesized_expression,
      ),

    for_in_expression: ($) =>
      seq(
        "for",
        $.quantifier,
        choice(
          sep1($.identifier, $._comma),
          seq($._lparen, sep1($.identifier, $._comma), $._rparen),
        ),
        "in",
        choice(
          $.range,
          seq($._lparen, sep1($._expression, $._comma), $._rparen),
          $.identifier,
          $.module_var_or_func
        ),
        $._colon,
        $.parenthesized_expression,
      ),

    of_expression: ($) => 
      prec.left(
        PREC.primary,
        seq($.quantifier, "of", $.string_set)
      ),

    quantifier: ($) =>
      choice("all", "any", "none", $._numeric_expression),

    _numeric_expression: ($) =>
      choice(
        $.integer_decimal_positive,
        $.integer_zero,
        $.integer_hexadecimal,
        $.float_literal,
        $.read_function_call,
        $.module_var_or_func,
        $.identifier,
        $.string_count,
        $.string_offset,
        $.string_length,
        $.filesize_keyword,
        $.parenthesized_numeric_expression,
        prec.left(PREC.multiplicative, seq($._numeric_expression, field("operator", choice("*", "\\", "%")), $._numeric_expression)),
        prec.left(PREC.additive, seq($._numeric_expression, field("operator", choice("+", "-")), $._numeric_expression)),
        prec.left(PREC.bit_shift, seq($._numeric_expression, field("operator", choice("<<", ">>")), $._numeric_expression)),
        prec.left(PREC.bit_and, seq($._numeric_expression, field("operator", "&"), $._numeric_expression)),
        prec.left(PREC.bit_xor, seq($._numeric_expression, field("operator", "^"), $._numeric_expression)),
        prec.left(PREC.bit_or, seq($._numeric_expression, field("operator", "|"), $._numeric_expression))
      ),

    string_set: ($) =>
      choice(
        "them",
        seq($._lparen, sep1(seq($.string_identifier, optional("*")), $._comma), $._rparen),
      ),

    rule_set: ($) => seq($._lparen, sep1(seq(alias($.identifier, $.rule), optional("*")), $._comma), $._rparen),
    of_ruleset: ($) => 
      prec.left(
        PREC.primary,
        seq($.quantifier, "of", $.rule_set)
      ),
    
    range: ($) =>
      seq($._lparen, $._numeric_expression, $._range2, $._numeric_expression, $._rparen),

    unary_expression: ($) =>
      choice(
        prec(
          PREC.unary,
          seq(
            field("operator", choice("not", "-", "~")),
            field("operand", $._expression),
          ),
        ),
        prec(
          PREC.not_defined,
          seq(
            field("operator", "not defined"),
            field("operand", $._expression),
          ),
        ),
      ),

    binary_expression: ($) =>
      choice(
        prec.left(
          PREC.comparative,
          seq(
            field("left", $._numeric_expression),
            field(
              "operator",
              choice(
                "<",
                "<=",
                ">",
                ">=",
              ),
            ),
            field("right", $._numeric_expression),
          ),
        ),
        prec.left(
          PREC.equality,
          seq(
            field("left", $._expression),
            field(
              "operator",
              choice(
                "==",
                "!=",
              ),
            ),
            field("right", $._expression),
          ),
        ),
        prec.left(
          PREC.equality,
          seq(
            field("left", $.string_expression),
            field(
              "operator",
              choice(
                "contains",
                "icontains",
                "startswith",
                "istartswith",
                "endswith",
                "iendswith",
                "iequals",
              ),
            ),
            field("right", $.string_expression),
          ),
        ),
        prec.left(
          PREC.equality,
          seq(
            field("left", $.string_expression),
            field("operator", "matches"),
            field("right", $.regular_expression),
          ),
        ),
        prec.left(
          PREC.and,
          seq(
            field("left", $._expression),
            field("operator", "and"),
            field("right", $._expression),
          ),
        ),
        prec.left(
          PREC.or,
          seq(
            field("left", $._expression),
            field("operator", "or"),
            field("right", $._expression),
          ),
        ),
      ),

    parenthesized_expression: ($) => seq($._lparen, $._expression, $._rparen),
    parenthesized_numeric_expression: ($) => seq($._lparen, $._numeric_expression, $._rparen),

    identifier: (_) => /[a-zA-Z_][a-zA-Z0-9_]*/,

    module_var_or_func: ($) =>
      prec.left(
        PREC.primary,
        seq(
          alias($.identifier, $.module_identifier),
          seq(
            ".",
            $.identifier,
            optional(seq($._lparen, optional(sep1($._expression, $._comma)), $._rparen))
          ),
          repeat(
            choice(
              seq(
                ".",
                $.identifier,
                optional(seq($._lparen, optional(sep1($._expression, $._comma)), $._rparen))
              ),
              seq($._lbrack, $._expression, $._rbrack)
            )
          )
        )
      ),


    comment: (_) =>
      token(
        choice(seq("//", /.*/), seq("/*", /[^*]*\*+([^/*][^*]*\*+)*/, "/")),
      ),
  },

  precedences: () => [
    ["binary_expression", "size_unit"],
    ["tag_list", "rule_body"]
  ],
});

function sep1(rule, separator) {
  return seq(rule, repeat(seq(separator, rule)));
}
