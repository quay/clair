// Copyright 2018 The Grafeas Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Filtering expression syntax.
parser grammar FilterExpression;

options { tokenVocab = FilterExpressionLexer; }

// Returns a filter expression.
filter
    : expression? WS* EOF
    ;

// Conjunction of sequences.
// e.g. `a AND b`
expression
    : expr=sequence (op+=andOp rest+=sequence)*
    ;

// Sequence of restrictions to be used for scoring list results.
// e.g. `a b 3.14`
sequence
    : expr=factor (WS+ rest+=factor)*
    ;

// Disjunction of terms.
// e.g. `a OR b`
factor
    : expr=term (op+=orOp rest+=term)*
    ;

// A restriction with optional negation.
// e.g. `NOT a`, `-a`
term
    : op=notOp? expr=restriction
    ;

// A comparable value with optional comparison.
// e.g. ordering: `a < b`, equality: `a = b`, membership: `a.b:*`
restriction
    : expr=comparable (WS* op=comparator WS* rest=comparable)?
    ;

// Comparables may either be numbers or values.
// NOTE: number is listed at a high precedence in order to avoid collisions
// between dot-delimited field selection within unquoted text and unambiguous
// classification of floating-point constants.
comparable
    : number
    | value
    ;

// The supported operator set.
comparator
    : LESS_EQUALS
    | LESS_THAN
    | GREATER_EQUALS
    | GREATER_THAN
    | NOT_EQUALS
    | EQUALS
    | HAS
    ;

// Values may either be index lookups or member expressions or a primary
// syntax node.
// e.g. index: `a[b]`, select: `a.b`, call: `a.b()`
value
    : primary                                             #PrimaryExpr
    | value op=DOT field (open=LPAREN argList? RPAREN)?   #SelectOrCall
    | value op=LBRACE WS* index=comparable WS* RBRACE     #DynamicIndex
    ;

// Primary expressions include [un]quoted text, variables, functions, or
// nested (composite) expressions.
// e.g. id: `a`, call: `id()`, quotedText: `"hello"`
//
// NOTE: the id node is ambiguous as to whether it should be interpreted
// as a variable identifier or unquoted text. Interpretation is left to
// filter evaluation.
primary
    : composite                                           #NestedExpr
    | id=text (open=LPAREN argList? RPAREN)?              #IdentOrGlobalCall
    | quotedText=STRING					                  #StringVal
    ;

// A list of function arguments.
argList
    : WS* args+=comparable (sep args+=comparable)* WS*
    ;

// Nested expression.
composite
    : LPAREN WS* expression WS* RPAREN
    ;

// Text will be treated as bareword identifier if possible. The interpretation
// is somewhat subject to the filter consumer; however, the values `true` and
// `false` (case-insensitive) will be treated as booleans.
text
    : (TEXT | EXCLAIM | DIGIT) (TEXT | EXCLAIM | DIGIT | MINUS)*
    ;

// Fields in a select statement are unambiguously string constants.
field
    : id=text
    | quotedText=STRING
    | keyword
    ;

// Numeric constants
number
    : floatVal
    | intVal
    ;

// Positive and negative integers with hex support.
intVal
    : MINUS? DIGIT+
    | MINUS? HEX_DIGIT
    ;

// Positive and negative floating point values.
floatVal
    : MINUS? (DIGIT+ DOT DIGIT* | DOT DIGIT+) EXPONENT?
    ;

// Convenience parse terms
notOp
    : MINUS
    | NOT WS+
    ;

andOp
    : WS+ AND WS+
    ;

orOp
    : WS+ OR WS+
    ;

sep
    : WS* COMMA WS*
    ;

keyword
    : OR
    | AND
    | NOT
    ;
