# Grafeas API Reference Implementation

This is a reference implementation of the [Grafeas API Spec](https://github.com/Grafeas/Grafeas/blob/master/README) 

## Overview

This reference implementation comes with the following caveats:
* Storage: map backed in memory server storage
* No ACLs are used in this implementation
* No authorization is in place #28
* Filtering in list methods is not currently supported #29
* Operation names are not currently validated when tied to notes/occurrences #31


### Running the server
To run the server, follow these simple steps:

```
go run main/main.go
```

