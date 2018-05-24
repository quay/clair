# Grafeas API Reference Implementation

This is a reference implementation of the [Grafeas API Spec](https://github.com/grafeas/grafeas/blob/master/README.md) 

## Overview

This reference implementation comes with the following caveats:
* No ACLs are used in this implementation
* No authorization is in place #28
* Filtering in list methods is not currently supported #29
* Operation names are not currently validated when tied to notes/occurrences #31


### Running the server
To run the server, follow these simple steps:

```
go run main/main.go
```

