# Legend
    -> outbound edges
    <- inbound edges

# Layer

    Key: "layer:" + Hash(id)

    -> is = "layer"
    -> id
    -> parent (my ancestor is)

    -> os
    -> adds*
    -> removes*
    -> engineVersion

    <- parent* (is ancestor of)

# Package

    Key: "package:" + Hash(os + ":" + name + ":" + version)

    -> is = "package"
    -> os
    -> name
    -> version
    -> nextVersion

    <- nextVersion
    <- adds*
    <- removes*
    <- fixed_in*

Packages are organized in linked lists : there is one linked list for one os/name couple. Each linked list has a tail and a head with special versions.

# Vulnerability

    Key: "vulnerability:" + Hash(name)

    -> is = "vulnerability"
    -> name
    -> priority
    -> link
    -> fixed_in*

# Notification

    Key: "notification:" + random uuid

    -> is = "notification"
    -> type
    -> data
    -> isSent

# Flag

    Key: "flag:" + name

    -> value

# Lock

    Key: name

    -> locked = "locked"
    -> locked_until (timestamp)
    -> locked_by

A lock can be used to lock a specific graph node by using the node Key as the lock name.
