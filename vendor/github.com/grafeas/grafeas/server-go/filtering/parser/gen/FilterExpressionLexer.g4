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

lexer grammar FilterExpressionLexer;

// Lexer Rules
// ===========

DOT       : '.';
HAS       : ':';
OR        : 'OR';
AND       : 'AND';
NOT       : 'NOT';
LPAREN    : '(';
RPAREN    : ')';
LBRACE    : '[';
RBRACE    : ']';
LBRACKET  : '{';
RBRACKET  : '}';
COMMA     : ',';
LESS_THAN : '<';
LESS_EQUALS : '<=';
GREATER_THAN : '>';
GREATER_EQUALS : '>=';
NOT_EQUALS : '!=';
EQUALS    : '=';
EXCLAIM   : '!';
MINUS     : '-';
PLUS      : '+';
STRING    : '"' Character* '"';
WS        : Whitespace;
DIGIT     : Digit;
HEX_DIGIT : '0x' HexDigit+;
EXPONENT  : Exponent;
TEXT      : (StartChar | TextEsc) (MidChar | TextEsc)*;
BACKSLASH : '\\';

fragment Character
    : ' ' | '!' | '#' .. '[' | ']' .. '~'
    | CharactersFromU00A1
    | TextEsc
    | '\\' ('a' | 'b' | 'f' | 'n' | 'r' | 't' | 'v')?
    | Whitespace
    ;

fragment TextEsc
    : EscapedChar
    | UnicodeEsc
    | OctalEsc
    | HexEsc
    ;

fragment UnicodeEsc
    : '\\' 'u' HexDigit HexDigit HexDigit HexDigit
    ;

fragment OctalEsc
    : '\\' [0-3]? OctalDigit? OctalDigit
    ;

fragment HexEsc
    : '\\x' HexDigit HexDigit
    ;

fragment Digit
    : [0-9]
    ;

fragment Exponent
    : [eE] (PLUS|MINUS)? Digit+
    ;

fragment HexDigit
    : Digit | [a-fA-F]
    ;

fragment OctalDigit
    : [0-7]
    ;

fragment StartChar
    : '#' .. '\''
    | '*'
    | '/'
    | ';'
    | '?'
    | '@'
    | [A-Z]
    | '^' .. 'z'
    | '|'
    | CharactersFromU00A1
    ;

fragment MidChar
    : StartChar
    | Digit
    | PLUS
    | MINUS
    ;

fragment EscapedChar
    : '\\' [:=<>+~"\\.*]
    ;

fragment Whitespace
    : (' '|'\r'|'\t'|'\u000C'|'\n')
    ;

fragment CharactersFromU00A1
    : '\u00A1' .. '\ufffe'
    ;

