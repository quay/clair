# Filter Baselines

The test baselines contain filter strings with the desired outputs separated by
50 `=` characters. Test cases within a baseline are separated by two newlines
`\n\n`. When the test case produces an error the line `<no result>` must appear
after the `=` separator, and the error output must appear after the
`Diagnostics:` line.

## Supported Format

```
a OR b
==================================================
expr: < ... >

~error-case
==================================================
<no result>
Diagnostics:
ERROR: ...
```

The baseline file must not end with an empty line as the line will be included
comparisions.

## Test Output

The baseline is self-contained in the sense that it capture the input and
expected output of the test. However, when there is a failure in the test, the
baseline case will be printed to stderr. At the moment, there is no support for
diffing actual versus expected baseline values, but this would be a nice future
refinement.