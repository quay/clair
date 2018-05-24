// Code generated from FilterExpression.g4 by ANTLR 4.7.1. DO NOT EDIT.

package gen // FilterExpression
import "github.com/antlr/antlr4/runtime/Go/antlr"

// A complete Visitor for a parse tree produced by FilterExpression.
type FilterExpressionVisitor interface {
	antlr.ParseTreeVisitor

	// Visit a parse tree produced by FilterExpression#filter.
	VisitFilter(ctx *FilterContext) interface{}

	// Visit a parse tree produced by FilterExpression#expression.
	VisitExpression(ctx *ExpressionContext) interface{}

	// Visit a parse tree produced by FilterExpression#sequence.
	VisitSequence(ctx *SequenceContext) interface{}

	// Visit a parse tree produced by FilterExpression#factor.
	VisitFactor(ctx *FactorContext) interface{}

	// Visit a parse tree produced by FilterExpression#term.
	VisitTerm(ctx *TermContext) interface{}

	// Visit a parse tree produced by FilterExpression#restriction.
	VisitRestriction(ctx *RestrictionContext) interface{}

	// Visit a parse tree produced by FilterExpression#comparable.
	VisitComparable(ctx *ComparableContext) interface{}

	// Visit a parse tree produced by FilterExpression#comparator.
	VisitComparator(ctx *ComparatorContext) interface{}

	// Visit a parse tree produced by FilterExpression#SelectOrCall.
	VisitSelectOrCall(ctx *SelectOrCallContext) interface{}

	// Visit a parse tree produced by FilterExpression#DynamicIndex.
	VisitDynamicIndex(ctx *DynamicIndexContext) interface{}

	// Visit a parse tree produced by FilterExpression#PrimaryExpr.
	VisitPrimaryExpr(ctx *PrimaryExprContext) interface{}

	// Visit a parse tree produced by FilterExpression#NestedExpr.
	VisitNestedExpr(ctx *NestedExprContext) interface{}

	// Visit a parse tree produced by FilterExpression#IdentOrGlobalCall.
	VisitIdentOrGlobalCall(ctx *IdentOrGlobalCallContext) interface{}

	// Visit a parse tree produced by FilterExpression#StringVal.
	VisitStringVal(ctx *StringValContext) interface{}

	// Visit a parse tree produced by FilterExpression#argList.
	VisitArgList(ctx *ArgListContext) interface{}

	// Visit a parse tree produced by FilterExpression#composite.
	VisitComposite(ctx *CompositeContext) interface{}

	// Visit a parse tree produced by FilterExpression#text.
	VisitText(ctx *TextContext) interface{}

	// Visit a parse tree produced by FilterExpression#field.
	VisitField(ctx *FieldContext) interface{}

	// Visit a parse tree produced by FilterExpression#number.
	VisitNumber(ctx *NumberContext) interface{}

	// Visit a parse tree produced by FilterExpression#intVal.
	VisitIntVal(ctx *IntValContext) interface{}

	// Visit a parse tree produced by FilterExpression#floatVal.
	VisitFloatVal(ctx *FloatValContext) interface{}

	// Visit a parse tree produced by FilterExpression#keyword.
	VisitKeyword(ctx *KeywordContext) interface{}

	// Visit a parse tree produced by FilterExpression#notOp.
	VisitNotOp(ctx *NotOpContext) interface{}

	// Visit a parse tree produced by FilterExpression#andOp.
	VisitAndOp(ctx *AndOpContext) interface{}

	// Visit a parse tree produced by FilterExpression#orOp.
	VisitOrOp(ctx *OrOpContext) interface{}

	// Visit a parse tree produced by FilterExpression#sep.
	VisitSep(ctx *SepContext) interface{}
}
