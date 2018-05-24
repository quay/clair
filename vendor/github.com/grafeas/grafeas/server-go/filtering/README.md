# Filtering

Filters are used with HTTP LIST operations to filter the result set. They can be
thought of as a simplified query language which provides support for applying
boolean expressions across the attributes of the records in the result set.

Filters can be extended with custom functions and can also express scoring
logic to help rank results which might be most relevant to the query. Filters
are not intended to be exact and may perform case-insensitive compares, 
corrections of common misspellings, or fuzzy matching. 

For a pratical example of list filters in production, see Google Cloud Logging's
[Advanced Filters](https://cloud.google.com/logging/docs/view/advanced-filters).

## Expressions

The following expressions, listed in order of operator precedence, are supported
by the parser included in the repository.

### Conjunction

The logical ANDing of two filters such as `a` and `b` in the example below.

```
a:property AND b('args', 2) AND -c 
```

The statement above parses as a series of function calls modelled as an AST
using the [common expression language](https://github.com/google/cel-spec):

```
and(
   has(a, property),
   and(b('args', 2), negation(c))
)
```

The logical AND may be used for result scoring, or as a requirement that all
results from the operation must adhere to. For more information about how the
conjunction is interpreted see the API documentation.

Note, the `AND` operator is case-sensitive. The following example illustrates
difference between `and` and `AND`

```
a AND b // parsed as and(a, b)
a and b // parsed as sequence(a, and, b)
```

### Sequence

Sequences are space-delimited expressions which may either be treated as 
equivalent to conjunctions representing strict requirements or as a result
scoring algorithm:

```
a.b = 'hello' a:world a.world != 'mars'
```

Parses to:

```
sequence(
   equals(select(a, b), 'hello'),
   has(a, world),
   notEquals(select(a, world), 'mars')
)
```

Sequences have lower precedence than conjunctions and higher precedence than
disjunctions, so it is most natural to read sequences as being grouped between
`AND` operators. 

The following example should be read as `and(a, sequence(or(b, c), d))`:

```
a AND b OR c d
```

### Disjunction

Disjunctions represent a logical ORing of restrictions. The example highlights
a series of restrictions ORed together. Note, that the timestamp string may
in some instance be treated as a timestamp by the API if `a` is a property of
timestamp type and the string on the right hand side is in a format compatible
with conversion from string to time such as
[RFC 3339](https://www.ietf.org/rfc/rfc3339.txt).

```
a >= '2018-03-06T00:00:00Z` OR b < text OR c = 1
```

### Negation

The `NOT` and `-` operator may be treated synonymously and are used to
expression exclusion result meeting a certain condition in the expression or
for expressing the inversion of a logical expression. How these expressions are
applied depends somewhat on the resource.

The following examples parse as `not(greater(a, b))`:

```
NOT (a > b)
NOT a > b
-a > b
```

To adjust the precedence to parse as `greater(not(a), b)`, use parentheses:

```
(-a) > b
```

### Restriction

There are restrictions for the common boolean expressions related to equality
and ordering.

*  Equality `=`
*  Inequality `!=`
*  Greater than `>`
*  Greater than or equal `>=`
*  Less than `<`
*  Less than or equal `<=`

In addition to the typical restrictions, there is also the `HAS` operator
indicated by the `:` which is used to test whether a property exists on a value.
This is useful when filtering table driven results with nullable column values. 

## Gotchas

Within the common expression langauge, all identifiers within an expression are
expected to be known at parse time. Within a list filter expression there are
scenarios where barewords (unquoted strings) in the expression may either be an
identifier or an unquoted string. How this ambiguity is resolved depends on the
filter interpreter implementation.

## Usage

The library expects the developer to provide a `Source` value, which could come
from a file, UI element, or URL query string to `parser.Parse()`. The output of
the `Parse` will be a `google.api.expr.v1.ParsedExpr` value or an error with a
formatted message indicating the location of the parse issue.