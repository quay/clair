# Filter Grammar

The filter grammar is based on the list filtering syntax supported by Google 
Cloud Logging's [Advanced Filters](https://cloud.google.com/logging/docs/view/advanced-filters).

The Antlr4 toolchain was used to model the grammar and generate go sources for
walking the parse tree (see the [installation instructions](https://github.com/antlr/antlr4/blob/master/doc/faq/installation.md)).
When updating a grammar file (*.g4), be sure to regenerate the source:

```
.../gen>antlr4 -no-listener -visitor -Dlanguage=Go -package gen FilterExpressionLexer.g4 FilterExpression.g4
```
