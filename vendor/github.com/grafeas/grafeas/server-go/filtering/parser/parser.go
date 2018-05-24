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

// package parser provides methods to parse filter sources to CEL-based ASTs.
package parser

import (
	"fmt"
	"strconv"

	"github.com/antlr/antlr4/runtime/Go/antlr"
	expr "github.com/google/cel-spec/proto/v1"
	"github.com/grafeas/grafeas/server-go/filtering/ast"
	"github.com/grafeas/grafeas/server-go/filtering/common"
	"github.com/grafeas/grafeas/server-go/filtering/operators"
	"github.com/grafeas/grafeas/server-go/filtering/parser/gen"
)

// Internal parser representation.
type parser struct {
	// Inherits from base visitor.
	gen.BaseFilterExpressionVisitor

	// Member values.
	nextId    int64
	positions map[int64]int32
	source    common.Source
	errors    *common.Errors
}

// Parse a filter source into an abstract CEL-based representation.
//
// The `Parse` method expects single `Source` value whose content will be
// parsed into a CEL representation that models the capabilities of the list
// filtering syntax supported by Google Cloud Logging's
// [Advanced Filters](https://cloud.google.com/logging/docs/view/advanced-filters)
//
// If the parse is not successful a `common.Errors` value is returned as the
// second result.
func Parse(source common.Source) (*expr.ParsedExpr, *common.Errors) {
	p := parser{
		nextId:    1,
		source:    source,
		positions: make(map[int64]int32),
		errors:    common.NewErrors(),
	}
	result := p.parse()
	if len(p.errors.GetErrors()) == 0 {
		return result, nil
	}
	return nil, p.errors
}

// Internal parse implementation.
func (p *parser) parse() *expr.ParsedExpr {
	stream := antlr.NewInputStream(p.source.Content())
	lexer := gen.NewFilterExpressionLexer(stream)
	parser := gen.NewFilterExpression(antlr.NewCommonTokenStream(lexer, 0))

	lexer.RemoveErrorListeners()
	parser.RemoveErrorListeners()
	lexer.AddErrorListener(p)
	parser.AddErrorListener(p)

	result := p.Visit(parser.Filter()).(*expr.Expr)
	sourceInfo := &expr.SourceInfo{
		Location:    p.source.Description(),
		LineOffsets: p.source.LineOffsets(),
		Positions:   p.positions,
	}
	return &expr.ParsedExpr{Expr: result, SourceInfo: sourceInfo}
}

// Visitor selection.
func (p *parser) Visit(tree antlr.ParseTree) interface{} {
	switch tree.(type) {
	case *gen.FilterContext:
		return p.VisitFilter(tree.(*gen.FilterContext))
	case *gen.ExpressionContext:
		return p.VisitExpression(tree.(*gen.ExpressionContext))
	case *gen.SequenceContext:
		return p.VisitSequence(tree.(*gen.SequenceContext))
	case *gen.FactorContext:
		return p.VisitFactor(tree.(*gen.FactorContext))
	case *gen.TermContext:
		return p.VisitTerm(tree.(*gen.TermContext))
	case *gen.RestrictionContext:
		return p.VisitRestriction(tree.(*gen.RestrictionContext))
	case *gen.ComparableContext:
		return p.VisitComparable(tree.(*gen.ComparableContext))
	case *gen.PrimaryExprContext:
		return p.VisitPrimaryExpr(tree.(*gen.PrimaryExprContext))
	case *gen.SelectOrCallContext:
		return p.VisitSelectOrCall(tree.(*gen.SelectOrCallContext))
	case *gen.DynamicIndexContext:
		return p.VisitDynamicIndex(tree.(*gen.DynamicIndexContext))
	case *gen.NestedExprContext:
		return p.Visit(tree.(*gen.NestedExprContext).Composite())
	case *gen.IdentOrGlobalCallContext:
		return p.VisitIdentOrGlobalCall(tree.(*gen.IdentOrGlobalCallContext))
	case *gen.ArgListContext:
		return p.VisitArgList(tree.(*gen.ArgListContext))
	case *gen.CompositeContext:
		return p.Visit(tree.(*gen.CompositeContext).Expression())
	case *gen.FieldContext:
		return p.VisitField(tree.(*gen.FieldContext))
	case *gen.StringValContext:
		return p.VisitStringVal(tree.(*gen.StringValContext))
	case *gen.NumberContext:
		return p.VisitNumber(tree.(*gen.NumberContext))
	case *gen.IntValContext:
		return p.VisitIntVal(tree.(*gen.IntValContext))
	case *gen.FloatValContext:
		return p.VisitFloatVal(tree.(*gen.FloatValContext))
	case *gen.KeywordContext,
		*gen.TextContext:
		return tree.GetText()
	}
	return p.newConst(tree, "<<error>>")
}

// Return the filter expression value.
func (p *parser) VisitFilter(ctx *gen.FilterContext) interface{} {
	if ctx.Expression() == nil {
		return &expr.Expr{Id: p.id(ctx)}
	}
	return p.Visit(ctx.Expression())
}

// Return a logically ANDed set of sequences.
func (p *parser) VisitExpression(ctx *gen.ExpressionContext) interface{} {
	var result = p.Visit(ctx.GetExpr()).(*expr.Expr)
	ops := ctx.GetOp()
	if ops == nil {
		return result
	}
	for i, sequence := range ctx.GetRest() {
		next := p.Visit(sequence).(*expr.Expr)
		op := ops[i]
		result = p.newCall(op, operators.LogicalAnd, []*expr.Expr{result, next})
	}
	return result
}

// Return a sequence of factors.
func (p *parser) VisitSequence(ctx *gen.SequenceContext) interface{} {
	result := p.Visit(ctx.GetExpr()).(*expr.Expr)
	if ctx.GetRest() == nil || len(ctx.GetRest()) == 0 {
		return result
	}
	args := make([]*expr.Expr, len(ctx.GetRest())+1)
	args[0] = result
	for i, factor := range ctx.GetRest() {
		index := i + 1
		args[index] = p.Visit(factor).(*expr.Expr)
	}
	return p.newCall(ctx, operators.Sequence, args)
}

// Return a logically ORed set of terms.
func (p *parser) VisitFactor(ctx *gen.FactorContext) interface{} {
	var result = p.Visit(ctx.GetExpr()).(*expr.Expr)
	ops := ctx.GetOp()
	if ops == nil {
		return result
	}
	for i, term := range ctx.GetRest() {
		next := p.Visit(term).(*expr.Expr)
		op := ops[i]
		result = p.newCall(op, operators.LogicalOr, []*expr.Expr{result, next})
	}
	return result
}

// Return an expression or unary operation.
func (p *parser) VisitTerm(ctx *gen.TermContext) interface{} {
	var result = p.Visit(ctx.GetExpr()).(*expr.Expr)
	// Negations and sequences apply only to restrictions, so if the output
	// of the restriction visitor is not a restriction, wrap the expression in
	// a Global restriction.
	if result.GetCallExpr() == nil ||
		!operators.IsRestriction(result.GetCallExpr().GetFunction()) {
		result = p.newCall(ctx, operators.Global, []*expr.Expr{result})
	}
	if ctx.GetOp() == nil {
		return result
	}
	return p.newCall(ctx.GetOp(),
		findOperator(ctx.GetOp()),
		[]*expr.Expr{result})
}

// Return a restriction expression, commonly equality, ordering, or presence.
// When a restriction returns a GLOBAL for an identifier, the global function
// must determine whether the identifier is bound to a value or whether to
// treat the identifier name as a string value within a Sequence.
func (p *parser) VisitRestriction(ctx *gen.RestrictionContext) interface{} {
	comparable := p.Visit(ctx.GetExpr()).(*expr.Expr)
	if ctx.GetOp() == nil {
		return comparable
	}
	arg := p.Visit(ctx.GetRest()).(*expr.Expr)
	return p.newCall(ctx.GetOp(),
		findOperator(ctx.GetOp()),
		[]*expr.Expr{comparable, arg})
}

// Visit either the numeric constant or value expresssion.
func (p *parser) VisitComparable(ctx *gen.ComparableContext) interface{} {
	if ctx.Number() != nil {
		return p.Visit(ctx.Number())
	}
	return p.Visit(ctx.Value())
}

// Visit the primary expression.
func (p *parser) VisitPrimaryExpr(ctx *gen.PrimaryExprContext) interface{} {
	return p.Visit(ctx.Primary())
}

// Return the select exprssion of qualified/member function call.
func (p *parser) VisitSelectOrCall(ctx *gen.SelectOrCallContext) interface{} {
	// Resolve the function target if one is present
	target := p.Visit(ctx.Value()).(*expr.Expr)
	field := p.Visit(ctx.Field()).(string)
	if ctx.GetOpen() == nil {
		return p.newSelect(ctx.GetOp(), target, field)
	}
	var args []*expr.Expr = nil
	if ctx.ArgList() != nil {
		args = p.Visit(ctx.ArgList()).([]*expr.Expr)
	}
	return p.newMemberCall(ctx.GetOpen(), field, target, args)
}

// Return a dynamically computed index into a value or list.
func (p *parser) VisitDynamicIndex(ctx *gen.DynamicIndexContext) interface{} {
	target := p.Visit(ctx.Value()).(*expr.Expr)
	index := p.Visit(ctx.GetIndex()).(*expr.Expr)
	return p.newCall(ctx.GetOp(), operators.Index, []*expr.Expr{target, index})
}

// Return an identifier or global function call expression.
func (p *parser) VisitIdentOrGlobalCall(
	ctx *gen.IdentOrGlobalCallContext) interface{} {
	id := p.Visit(ctx.GetId()).(string)
	if ctx.GetOpen() == nil {
		return p.newIdent(ctx, id)
	}
	var args []*expr.Expr = nil
	if ctx.ArgList() != nil {
		args = p.Visit(ctx.ArgList()).([]*expr.Expr)
	}
	return p.newCall(ctx.GetOpen(), id, args)
}

// Return a list of Expr values to be used as arguments.
func (p *parser) VisitArgList(ctx *gen.ArgListContext) interface{} {
	exprArgs := make([]*expr.Expr, len(ctx.GetArgs()))
	for i, arg := range ctx.GetArgs() {
		exprArgs[i] = p.Visit(arg).(*expr.Expr)
	}
	return exprArgs
}

// Return a string field name for use with a selected field or qualified
// function.
func (p *parser) VisitField(ctx *gen.FieldContext) interface{} {
	if ctx.Keyword() != nil {
		return p.Visit(ctx.Keyword())
	}
	if ctx.GetQuotedText() != nil {
		return p.unquote(ctx, ctx.GetQuotedText().GetText())
	}
	return p.Visit(ctx.GetId())
}

// Return a string constant value.
// Different filter consumers may choose to support conventions for converting
// a string to a Timestamp or Duration. This parser does not attempt any more
// intelligent interpretation of the literal.
func (p *parser) VisitStringVal(ctx *gen.StringValContext) interface{} {
	text := ctx.GetText()
	return p.newConst(ctx, p.unquote(ctx, text))
}

func (p *parser) VisitNumber(ctx *gen.NumberContext) interface{} {
	if ctx.FloatVal() != nil {
		return p.Visit(ctx.FloatVal())
	}
	return p.Visit(ctx.IntVal())
}

// Return an int64 value from the parsed string.
func (p *parser) VisitIntVal(ctx *gen.IntValContext) interface{} {
	text := ctx.GetText()
	val, err := strconv.ParseInt(text, 0, 64)
	if err == nil {
		return p.newConst(ctx, val)
	}
	p.errors.ReportError(
		p.source,
		common.Location(ctx.GetStart()),
		fmt.Sprintf("Unrecognized integer value: %s", text))
	return p.newConst(ctx, "<<error>>")
}

// Return a float64 value from the parsed string.
func (p *parser) VisitFloatVal(ctx *gen.FloatValContext) interface{} {
	text := ctx.GetText()
	val, err := strconv.ParseFloat(text, 64)
	if err == nil {
		return p.newConst(ctx, val)
	}
	p.errors.ReportError(
		p.source,
		common.Location(ctx.GetStart()),
		fmt.Sprintf("Unrecognized floating point value: %s", text))
	return p.newConst(ctx, "<<error>>")
}

// Listener implementations
func (p *parser) SyntaxError(recognizer antlr.Recognizer,
	offendingSymbol interface{}, line, column int, msg string,
	e antlr.RecognitionException) {
	var errorMsg = "Syntax error"
	switch e.(type) {
	case antlr.InputMisMatchException:
		errorMsg = "Input mismatch"
	case antlr.NoViableAltException:
		errorMsg = "Unexpected token"
	}
	p.errors.ReportError(p.source, common.NewLocation(line, column), errorMsg)
}

// Ambiguities in the grammar can arise under rare circumstances, but typically
// only add a small look-ahead burden on parsing, where some number of lex
// tokens must be read before disambiguation can be done for the parse term.
func (p *parser) ReportAmbiguity(recognizer antlr.Parser, dfa *antlr.DFA,
	startIndex, stopIndex int, exact bool, ambigAlts *antlr.BitSet,
	configs antlr.ATNConfigSet) {
	// Intentional
}

// Indicates some added parsing overhead, but nothing problematic.
func (p *parser) ReportAttemptingFullContext(recognizer antlr.Parser,
	dfa *antlr.DFA, startIndex, stopIndex int,
	conflictingAlts *antlr.BitSet, configs antlr.ATNConfigSet) {
	// Intentional
}

// Indicates some added parsing overhead, but nothing problematic.
func (p *parser) ReportContextSensitivity(recognizer antlr.Parser,
	dfa *antlr.DFA, startIndex, stopIndex, prediction int,
	configs antlr.ATNConfigSet) {
	// Intentional
}

// Helper functions for attaching source context to the expression node.
func (p *parser) newIdent(token interface{}, name string) *expr.Expr {
	return ast.NewIdent(p.id(token), name)
}

func (p *parser) newSelect(token interface{}, operand *expr.Expr,
	field string) *expr.Expr {
	return ast.NewSelect(p.id(token), operand, field)
}

func (p *parser) newConst(token interface{}, value interface{}) *expr.Expr {
	return ast.NewConst(p.id(token), value)
}

func (p *parser) newCall(token interface{}, name string,
	args []*expr.Expr) *expr.Expr {
	return p.newMemberCall(token, name, nil, args)
}

func (p *parser) newMemberCall(token interface{}, name string,
	target *expr.Expr, args []*expr.Expr) *expr.Expr {
	return ast.NewCall(p.id(token), name, target, args)
}

func (p *parser) id(ctx interface{}) int64 {
	var token antlr.Token = nil
	switch ctx.(type) {
	case antlr.ParserRuleContext:
		token = (ctx.(antlr.ParserRuleContext)).GetStart()
	case antlr.Token:
		token = ctx.(antlr.Token)
	default:
		// This should only happen if the ctx is nil
		return -1
	}
	location := common.Location(token)
	id := p.nextId
	p.positions[id], _ = p.source.CharacterOffset(location)
	p.nextId++
	return id
}

func (p *parser) unquote(ctx antlr.ParserRuleContext, value string) string {
	if text, err := strconv.Unquote(value); err == nil {
		return text
	}
	p.errors.ReportError(p.source, common.Location(ctx.GetStart()),
		"Unable to unquote string")
	return value
}

func findOperator(value antlr.ParseTree) string {
	op := value.GetText()
	if name, found := operators.Find(op); found {
		return name
	}
	return op
}
