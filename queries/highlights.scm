; tree-sitter-yara: highlights.scm
    ; Designed for the current grammar.js in this repository.

    ; Comments
    (comment) @comment

    ; Top-level / structural keywords
    "import" @keyword
    "include" @keyword
    "rule" @keyword
    "private" @keyword
    "global" @keyword
    "meta" @keyword
    "strings" @keyword
    "condition" @keyword

    ; Condition keywords / operators
    "for" @keyword
    "in" @keyword
    "of" @keyword
    "all" @keyword
    "any" @keyword
    "none" @keyword
    "defined" @keyword
    "not" @keyword

    "and" @operator
    "or" @operator
    "matches" @operator
    "contains" @operator
    "icontains" @operator
    "startswith" @operator
    "istartswith" @operator
    "endswith" @operator
    "iendswith" @operator
    "iequals" @operator

    "==" @operator
    "!=" @operator
    "<" @operator
    ">" @operator
    "<=" @operator
    ">=" @operator
    "&" @operator
    "|" @operator
    "^" @operator
    "~" @operator
    "+" @operator
    "-" @operator
    "*" @operator
    "/" @operator
    "%" @operator

    "at" @operator

    ; Built-ins / literals
    (filesize_keyword) @constant.builtin
    (boolean_literal) @constant.builtin
    (read_function_name) @function.builtin
    (size_unit) @constant
    (integer_decimal_positive) @number
    (integer_zero) @number
    (integer_hexadecimal) @number
    (float_literal) @number

    ; Strings
    (double_quoted_string) @string
    (single_quoted_string) @string
    (text_string) @string
    (escape_sequence) @string.escape
    (regular_expression) @string.regexp

    ; Hex strings / hex components
    (hex_seq) @constant.numeric
    (hex_jump) @constant.numeric
    (hex_byte) @constant.numeric

    ; Identifiers / names
    (rule_definition
      name: (identifier) @function)

    (string_definition
      name: (string_identifier) @variable.builtin)

    (meta_definition
      key: (identifier) @property)

    (module_var_or_func
      module_name: (module_identifier) @namespace
      name: (identifier) @property)

    (module_identifier) @namespace
    (identifier) @variable
    (string_identifier) @variable.builtin

    ; Tags
    (tag) @tag

    ; Modifiers
    "nocase" @keyword.modifier
    "ascii" @keyword.modifier
    "wide" @keyword.modifier
    "fullword" @keyword.modifier
    "xor" @keyword.modifier
    "base64" @keyword.modifier
    "base64wide" @keyword.modifier
    "private" @keyword.modifier

    ; Punctuation / delimiters
    [
      "="
      ":"
      "{"
      "}"
      "["
      "]"
      "("
      ")"
      ","
      "|"
      "."
      ".."
    ] @punctuation.delimiter
