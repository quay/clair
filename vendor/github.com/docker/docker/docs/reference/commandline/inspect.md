---
title: "inspect"
description: "The inspect command description and usage"
keywords: "inspect, container, json"
---

<!-- This file is maintained within the docker/docker Github
     repository at https://github.com/docker/docker/. Make all
     pull requests against that repo. If you see this file in
     another repository, consider it read-only there, as it will
     periodically be overwritten by the definitive file. Pull
     requests which include edits to this file in other repositories
     will be rejected.
-->

# inspect

```markdown
Usage:  docker inspect [OPTIONS] NAME|ID [NAME|ID...]

Return low-level information on Docker object(s) (e.g. container, image, volume,
network, node, service, or task) identified by name or ID

Options:
  -f, --format       Format the output using the given Go template
      --help         Print usage
  -s, --size         Display total file sizes if the type is container
      --type         Return JSON for specified type
```

By default, this will render all results in a JSON array. If the container and
image have the same name, this will return container JSON for unspecified type.
If a format is specified, the given template will be executed for each result.

Go's [text/template](http://golang.org/pkg/text/template/) package
describes all the details of the format.

## Examples

**Get an instance's IP address:**

For the most part, you can pick out any field from the JSON in a fairly
straightforward manner.

    {% raw %}
    $ docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $INSTANCE_ID
    {% endraw %}

**Get an instance's MAC address:**

For the most part, you can pick out any field from the JSON in a fairly
straightforward manner.

    {% raw %}
    $ docker inspect --format='{{range .NetworkSettings.Networks}}{{.MacAddress}}{{end}}' $INSTANCE_ID
    {% endraw %}

**Get an instance's log path:**

    {% raw %}
    $ docker inspect --format='{{.LogPath}}' $INSTANCE_ID
    {% endraw %}

**Get a Task's image name:**

    {% raw %}
    $ docker inspect --format='{{.Container.Spec.Image}}' $INSTANCE_ID
    {% endraw %}

**List all port bindings:**

One can loop over arrays and maps in the results to produce simple text
output:

    {% raw %}
    $ docker inspect --format='{{range $p, $conf := .NetworkSettings.Ports}} {{$p}} -> {{(index $conf 0).HostPort}} {{end}}' $INSTANCE_ID
    {% endraw %}

**Find a specific port mapping:**

The `.Field` syntax doesn't work when the field name begins with a
number, but the template language's `index` function does. The
`.NetworkSettings.Ports` section contains a map of the internal port
mappings to a list of external address/port objects. To grab just the
numeric public port, you use `index` to find the specific port map, and
then `index` 0 contains the first object inside of that. Then we ask for
the `HostPort` field to get the public address.

    {% raw %}
    $ docker inspect --format='{{(index (index .NetworkSettings.Ports "8787/tcp") 0).HostPort}}' $INSTANCE_ID
    {% endraw %}

**Get a subsection in JSON format:**

If you request a field which is itself a structure containing other
fields, by default you get a Go-style dump of the inner values.
Docker adds a template function, `json`, which can be applied to get
results in JSON format.

    {% raw %}
    $ docker inspect --format='{{json .Config}}' $INSTANCE_ID
    {% endraw %}
