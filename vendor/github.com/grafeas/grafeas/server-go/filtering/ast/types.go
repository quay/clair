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

// package ast provides methods for constructing CEL abstract syntax nodes.
package ast

import (
	expr "github.com/google/cel-spec/proto/v1"
)

// Create a constant from the primitive value with the given id.
func NewConst(id int64, value interface{}) *expr.Expr {
	constant := expr.Constant{}
	switch value.(type) {
	case int64:
		constant.ConstantKind =
			&expr.Constant_Int64Value{Int64Value: value.(int64)}
	case uint64:
		constant.ConstantKind =
			&expr.Constant_Uint64Value{Uint64Value: value.(uint64)}
	case float64:
		constant.ConstantKind =
			&expr.Constant_DoubleValue{DoubleValue: value.(float64)}
	// The advanced list filtering documentation indicates support
	// for converting strings with specific formats into other constant
	// type values. This is left as an exercise for the evaluator as
	// the interpretation of the string type is often contextual.
	case string:
		constant.ConstantKind =
			&expr.Constant_StringValue{StringValue: value.(string)}
	}
	return newExpr(id, &constant)
}

// Create an identifier from the given name and id.
//
// Identifiers may either refer to a property that can be filtered within the
// API, or unquoted text. Interpretation of an identifier is highly contextual.
//
// Within CEL, type-checking asserts that all identifiers must be declared. To
// use type-checking with filters, a second processing step may be used to
// convert unknown identifiers to constant strings prior to the type-check. This
// may be desired as an algorithmic way for validating filters.
func NewIdent(id int64, name string) *expr.Expr {
	return newExpr(id, &expr.Expr_Ident{Name: name})
}

// Create a select field expression from the operand, field name, and id.
//
// Selection occurs via the dot operator, but there is also an index expression
// which permits the selection of a field with non-identifier characters in it.
func NewSelect(id int64, operand *expr.Expr, field string) *expr.Expr {
	return newExpr(id, &expr.Expr_Select{Operand: operand, Field: field})
}

// Create a function call expression from the function name, optional receiver,
// arguments, and id.
//
// All operators and user-defined functions are modelled as calls. For a list
// of built-in operators (restrictions), see the operators/operators.go file.
func NewCall(id int64, name string, target *expr.Expr, args []*expr.Expr) *expr.Expr {
	return newExpr(id, &expr.Expr_Call{Function: name, Target: target, Args: args})
}

// Create a new expression from the given id and kind.
// Ast nodes must have a unique id which will be associated with source metadata.
func newExpr(id int64, kind interface{}) *expr.Expr {
	value := expr.Expr{Id: id}
	switch kind.(type) {
	case *expr.Expr_Ident:
		value.ExprKind =
			&expr.Expr_IdentExpr{IdentExpr: kind.(*expr.Expr_Ident)}
	case *expr.Expr_Select:
		value.ExprKind =
			&expr.Expr_SelectExpr{SelectExpr: kind.(*expr.Expr_Select)}
	case *expr.Expr_Call:
		value.ExprKind =
			&expr.Expr_CallExpr{CallExpr: kind.(*expr.Expr_Call)}
	case *expr.Constant:
		value.ExprKind =
			&expr.Expr_ConstExpr{ConstExpr: kind.(*expr.Constant)}
	case nil:
		// do nothing
	}
	return &value
}
