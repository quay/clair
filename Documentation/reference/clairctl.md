# Clairctl

`clairctl` is a command line tool for working with ClairV4. 
This CLI is capable of generating manifests from most public registires (docker, quay.io, redhat container catalog) and submitting them for analysis to a running ClairV4.


```
NAME:
   clairctl - A new cli application

USAGE:
   clairctl [global options] command [command options] [arguments...]

VERSION:
   0.1.0

DESCRIPTION:
   A command-line tool for clair v4.

COMMANDS:
   manifest  
   report    request vulnerability reports for the named containers
   help, h   Shows a list of commands or help for one command

GLOBAL OPTIONS:
   -D             print debugging logs (default: false)
   --help, -h     show help (default: false)
   --version, -v  print the version (default: false)
```

```
NAME:
   clairctl manifest - 

USAGE:
   clairctl manifest [command options] [arguments...]

DESCRIPTION:
   print a clair manifest for the provided container

OPTIONS:
   --help, -h  show help (default: false)
```


```
NAME:
   clairctl report - request vulnerability reports for the named containers

USAGE:
   clairctl report [command options] container...

DESCRIPTION:
   Request and print a Clair vulnerability report for the provided container(s).

OPTIONS:
   --host value           URL for the clairv4 v1 API. (default: "http://localhost:6060/")
   --out value, -o value  output format: text, json, xml (default: text)
   --help, -h             show help (default: false)
```
