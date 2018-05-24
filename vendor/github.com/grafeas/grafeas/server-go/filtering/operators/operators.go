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

// package operators defines constant operator names and helper functions for
// identifying the operator and its kind.
package operators

import "strings"

// All CEL operators are modelled as function calls. The list of constants below
// uses mangled operator names to avoid collisions with user-defined functions.
const (
	Sequence   = "_sequence_" // Sequence of conjunctions.
	LogicalAnd = "_&&_"       // Conjunction operator (a AND b).
	LogicalOr  = "_||_"       // Disjunction operator (a OR b).
	LogicalNot = "_!"         // Negation using the keyword NOT
	Negate     = "-_"         // Negation using the minus
	Index      = "_[_]"       // Index operation on a map or list.

	// Restriction operations.
	Global        = "_global_"
	Has           = "_:_"
	Equals        = "_==_"
	Greater       = "_>_"
	GreaterEquals = "_>=_"
	Less          = "_<_"
	LessEquals    = "_<=_"
	NotEquals     = "_!=_"
)

var (
	// Mapping between textual operator strings and mangled operator names.
	operators = map[string]string{
		"AND": LogicalAnd,
		"OR":  LogicalOr,
		"NOT": LogicalNot,
		"-":   Negate,
		"[":   Index,
		":":   Has,
		"=":   Equals,
		"!=":  NotEquals,
		"<":   Less,
		"<=":  LessEquals,
		">":   Greater,
		">=":  GreaterEquals,
	}

	// The set of operators that are also restrictions.
	restrictions = []string{
		Global,
		Has,
		Equals,
		NotEquals,
		Less,
		LessEquals,
		Greater,
		GreaterEquals,
	}
)

// Find the operator name from the function name and whether it could be found.
func Find(text string) (string, bool) {
	op, found := operators[strings.Trim(text, " ")]
	return op, found
}

// Determine whether the operator is a restriction.
func IsRestriction(op string) bool {
	trimmed := strings.Trim(op, " ")
	for _, restriction := range restrictions {
		if restriction == trimmed {
			return true
		}
	}
	return false
}
