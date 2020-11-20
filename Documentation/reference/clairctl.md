# Clairctl

`clairctl` is a command line tool for working with Clair.
This CLI is capable of generating manifests from most public registries
(dockerhub, quay.io, Red Hat Container Catalog) and submitting them for
analysis to a running Clair.

Note that if the Clair instance has authentication configured, the value
provided to the `issuer` flag must be on the list accepted by the server.

```
NAME:
   clairctl - interact with a clair API

USAGE:
   clairctl [global options] command [command options] [arguments...]

VERSION:
   0.1.0

DESCRIPTION:
   A command-line tool for clair v4.

COMMANDS:
   manifest         print a clair manifest for the named container
   report           request vulnerability reports for the named containers
   export-updaters  run updaters and export results
   import-updaters  import updates
   help, h          Shows a list of commands or help for one command

GLOBAL OPTIONS:
   -D                           print debugging logs (default: false)
   --config value, -c value     clair configuration file (default: "config.yaml") [$CLAIR_CONF]
   --issuer value, --iss value  jwt "issuer" to use when making authenticated requests (default: "clairctl")
   --help, -h                   show help (default: false)
   --version, -v                print the version (default: false)
```

```
NAME:
   clairctl manifest - print a clair manifest for the named container

USAGE:
   clairctl manifest [arguments...]

DESCRIPTION:
   print a clair manifest for the named container
```

```
NAME:
   clairctl report - request vulnerability reports for the named containers

USAGE:
   clairctl report [command options] container...

DESCRIPTION:
   Request and print a Clair vulnerability report for the named container(s).

OPTIONS:
   --host value           URL for the clairv4 v1 API. (default: "http://localhost:6060/") [$CLAIR_API]
   --out value, -o value  output format: text, json, xml (default: text)
```

```
NAME:
   clairctl export-updaters - run updaters and export results

USAGE:
   clairctl export-updaters [command options] [out]

DESCRIPTION:
   Run configured exporters and export to a file.

   A configuration file is needed to run this command, see 'clairctl help'
   for how to specify one.

OPTIONS:
   --strict  Return non-zero exit when updaters report errors. (default: false)
```

```
NAME:
   clairctl import-updaters - import updates

USAGE:
   clairctl import-updaters input...

DESCRIPTION:
   Import updates from files or HTTP URIs.

   A configuration file is needed to run this command, see 'clairctl help'
   for how to specify one.
```
