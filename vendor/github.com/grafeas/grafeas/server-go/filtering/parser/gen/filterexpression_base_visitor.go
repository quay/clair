// Code generated from FilterExpression.g4 by ANTLR 4.7.1. DO NOT EDIT.

package gen // FilterExpression
import "github.com/antlr/antlr4/runtime/Go/antlr"

type BaseFilterExpressionVisitor struct {
	*antlr.BaseParseTreeVisitor
}

func (v *BaseFilterExpressionVisitor) VisitFilter(ctx *FilterContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseFilterExpressionVisitor) VisitExpression(ctx *ExpressionContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseFilterExpressionVisitor) VisitSequence(ctx *SequenceContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseFilterExpressionVisitor) VisitFactor(ctx *FactorContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseFilterExpressionVisitor) VisitTerm(ctx *TermContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseFilterExpressionVisitor) VisitRestriction(ctx *RestrictionContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseFilterExpressionVisitor) VisitComparable(ctx *ComparableContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseFilterExpressionVisitor) VisitComparator(ctx *ComparatorContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseFilterExpressionVisitor) VisitSelectOrCall(ctx *SelectOrCallContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseFilterExpressionVisitor) VisitDynamicIndex(ctx *DynamicIndexContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseFilterExpressionVisitor) VisitPrimaryExpr(ctx *PrimaryExprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseFilterExpressionVisitor) VisitNestedExpr(ctx *NestedExprContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseFilterExpressionVisitor) VisitIdentOrGlobalCall(ctx *IdentOrGlobalCallContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseFilterExpressionVisitor) VisitStringVal(ctx *StringValContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseFilterExpressionVisitor) VisitArgList(ctx *ArgListContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseFilterExpressionVisitor) VisitComposite(ctx *CompositeContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseFilterExpressionVisitor) VisitText(ctx *TextContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseFilterExpressionVisitor) VisitField(ctx *FieldContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseFilterExpressionVisitor) VisitNumber(ctx *NumberContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseFilterExpressionVisitor) VisitIntVal(ctx *IntValContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseFilterExpressionVisitor) VisitFloatVal(ctx *FloatValContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseFilterExpressionVisitor) VisitKeyword(ctx *KeywordContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseFilterExpressionVisitor) VisitNotOp(ctx *NotOpContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseFilterExpressionVisitor) VisitAndOp(ctx *AndOpContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseFilterExpressionVisitor) VisitOrOp(ctx *OrOpContext) interface{} {
	return v.VisitChildren(ctx)
}

func (v *BaseFilterExpressionVisitor) VisitSep(ctx *SepContext) interface{} {
	return v.VisitChildren(ctx)
}
