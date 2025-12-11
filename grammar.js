/**
 * @file Tree-sitter plugin for the Yara language.
 * @author egibs <evan@egibs.xyz>, @author celstur
 * @license MIT
 */

/// <reference types="tree-sitter-cli/dsl" />
// @ts-check

const PREC = {
  primary: 7,
  unary: 6,
  multiplicative: 5,
  additive: 4,
  comparative: 3,
  and: 2,
  or: 1,
};

module.exports = grammar({
  name: "yara",

  extras: ($) => [$.comment, /[\s\f\uFEFF\u2060\u200B]|\r?\n/],

  word: ($) => $.identifier,

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

    import_statement: ($) => seq("import", $.string_literal),

    include_statement: ($) => seq("include", $.string_literal),

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
          choice($.string_literal, choice($.integer_zero, $.integer_decimal_positive), $.boolean_literal),
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

    string_identifier: (_) => token(/\$[a-zA-Z_][a-zA-Z0-9_]*|\$/),

    text_string: ($) =>
      choice(
        seq(
          $._quote,
          repeat(choice($.text_string_esc_seq, /[^"\\]+/)),
          $._quote
        ),
        seq(
          $._squote,
          repeat(choice($.text_string_esc_seq, /[^"\\]+/)),
          $._squote
        )),

    text_string_esc_seq: (_) =>
      token.immediate(seq('\\', choice(/["\\rtn]/, /x[0-9A-Fa-f]{2}/))),

    hex_string: ($) =>
      seq(
        $._lbrace,
        repeat1(
          choice($.hex_string_byte, $.hex_jump, $.hex_alternative),
        ),
        $._rbrace,
      ),
    hex_string_byte: (_) => /~?[0-9a-fA-F?]{2}/,
    hex_seq: ($) => seq($.hex_string_byte, repeat1($.hex_string_byte)),
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
      seq($._lparen, sep1(choice($.hex_string_byte, $.hex_seq), $._pipe), $._rparen),

    regex_string: ($) =>
      prec.right(
        1,
        seq(
          $._slash,
          alias($.regex_string_content, $.pattern),
          $._slash,
          optional($.string_modifiers),
        ),
      ),
    regex_string_content: ($) =>
      repeat1(choice(token.immediate(/[^\/\\]+/), $.escape_sequence)),

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
        $.identifier,
        $.string_identifier,
        $.module_var_or_func,
        $.integer_decimal_positive,
        $.integer_zero,
        $.integer_hexadecimal,
        $.boolean_literal,
        $.string_literal,
        $.string_count,
        $.string_offset,
        $.string_at_offset,
        $.string_at_range, 
        $.string_length,
        $.filesize_keyword,
        $.read_function_call,
        $.for_of_expression,
        $.for_in_expression,
        $.of_expression,
        $.parenthesized_expression,
        $.unary_expression,
        $.binary_expression,
      ),

    filesize_keyword: (_) => "filesize",

    size_unit: (_) => choice("KB", "MB", "GB"),

    integer_decimal_positive: ($) => seq(/[0]*[1-9][0-9]*/, optional($.size_unit)),
    integer_zero: ($) => seq(/[0]+/, optional($.size_unit)),
    integer_hexadecimal: ($) => /0x[0-9A-Fa-f]+/,
    hex_byte: (_) => /0x[0-9A-Fa-f]{2}|25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]/,
    boolean_literal: (_) => choice("true", "false"),
    string_literal: ($) =>
      choice($.double_quoted_string, $.single_quoted_string),

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
          optional(seq($._lbrack, $._expression, $._rbrack))
        ),
        token(/@/)
      ),
    string_at_offset: ($) =>
      prec.left(
        PREC.comparative,
        seq(
          choice($.string_identifier, $.of_expression),
          "at",
          $._expression
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
          optional(seq($._lbrack, $._expression, $._rbrack))
        ),
        token(/!/)
      ),

    read_function_name: (_) => choice(
      "int8", "int16", "int32",
      "uint8", "uint16", "uint32",
      "int8be", "int16be", "int32be",
      "uint8be", "uint16be", "uint32be",
    ),
    read_function_call: ($) => seq($.read_function_name, $._lparen, $._expression, $._rparen),

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
        sep1($.identifier, $._comma),
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

    of_expression: ($) => seq($.quantifier, "of", $.string_set),

    quantifier: ($) =>
      choice("all", "any", "none", $._expression),

    string_set: ($) =>
      choice(
        "them",
        seq($._lparen, sep1(seq($.string_identifier, optional("*")), $._comma), $._rparen),
      ),

    range: ($) =>
      seq($._lparen, $._expression, $._range2, $._expression, $._rparen),

    unary_expression: ($) =>
      prec(
        PREC.unary,
        seq(
          field("operator", choice("not", "-", "~")),
          field("operand", $._expression),
        ),
      ),

    binary_expression: ($) =>
      choice(
        prec.left(
          PREC.multiplicative,
          seq(
            field("left", $._expression),
            field("operator", choice("*", "\\", "%")),
            field("right", $._expression),
          ),
        ),
        prec.left(
          PREC.additive,
          seq(
            field("left", $._expression),
            field("operator", choice("+", "-")),
            field("right", $._expression),
          ),
        ),
        prec.left(
          PREC.comparative,
          seq(
            field("left", $._expression),
            field(
              "operator",
              choice(
                "==",
                "!=",
                "<",
                "<=",
                ">",
                ">=",
                "contains",
                "matches",
                "icontains",
                "imatches",
                "startswith",
                "istartswith",
                "endswith",
                "iendswith",
              ),
            ),
            field("right", $._expression),
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

    identifier: (_) => /[a-zA-Z_][a-zA-Z0-9_]*/,

    module_var_or_func: ($) =>
      seq(
        $.identifier,
        ".",
        $.identifier,
        optional(seq($._lparen, optional($._expression), $._rparen)),
      ),

    comment: (_) =>
      token(
        choice(seq("//", /.*/), seq("/*", /[^*]*\*+([^/*][^*]*\*+)*/, "/")),
      ),
  },

  precedences: () => [
    ["binary_expression", "size_unit"],
    ["tag_list", "rule_body"],
  ],
});

function sep1(rule, separator) {
  return seq(rule, repeat(seq(separator, rule)));
}
