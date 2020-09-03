# Deploying ClairV4

ClairV4 was designed with flexible deployment architectures in mind. The operator is free to choose a deployment model which scales to their use cases. 

## Configuration

Before jumping directly into the models its important to note that ClairV4 is capable of using a single configuration file across all node types. This design decision makes it very easy to deploy on systems like Kubernetes and Openshift.

See [Config Reference](../reference/config.md)

## Combined Deployment

In a combined deployment all node types run on in a single Clair process. This is by far the easiest deployment model to configure as it involves the least moving parts. 

A load balancer is still recommended if you plan on performing TLS termination. Typically this will be a Openshift route or a Kubernetes ingress.

![combo mode single db deployment diagran](./clairv4_combo_single_db.png)

In the above diagram Clair is running in combo mode and talking to a single database. To configure this model you will provide all node types the same database and start clair in **combo** mode.

```
...
indexer:
    connstring: "host=clairdb user=pqgotest dbname=pqgotest sslmode=verify-full"
matcher:
    connstring: "host=cher-clairdb user=pqgotest dbname=pqgotest sslmode=verify-full"
    ...
notifier:
    connstring: "host=clairdb user=pqgotest dbname=pqgotest sslmode=verify-full"
    ...
```
In this mode any configuration informing Clair how to talk to other nodes is ignored, it is not needed as all api communication is done in process.

For added flexibility its also supported to split the databases while in combo mode.

![combo mode multiple db deployment diagran](./clairv4_combo_multi_db.png)

In the above diagram Clair is running in combo mode but database load is split between multiple databases. Since Clair is conceptually a set of micro-services, nodes communicate over API and do not share database tables.

To configure this model you would provide each node type it's own "connstring" in the configuration. 
```
...
indexer:
    connstring: "host=indexer-clairdb user=pqgotest dbname=pqgotest sslmode=verify-full"
matcher:
    connstring: "host=matcher-clairdb user=pqgotest dbname=pqgotest sslmode=verify-full"
    ...
notifier:
    connstring: "host=notifier-clairdb user=pqgotest dbname=pqgotest sslmode=verify-full"
    ...
```

## Distributed Deployment

If your application needs to asymetrically scale or you expect high load you may want to consider a distributed deployment.

In a distributed deployment each Clair node type runs in its own process. Typically this will be a Kubernetes\Openshift deployment or your public cloud of choice's auto scaling mechanism.

A load balancer **must** be setup in this deployment model. The load balancer will route traffic between Clair nodes along with routing API requests via [path based routing](https://devcentral.f5.com/s/articles/the-three-http-routing-patterns-you-should-know-30764) to the correct services. In a Kubernetes or Openshift deployment this is usually trivialized by the Service and Routes abstractions. If you will be deploying on bare metal you will need to configure a load balancer appropriately. 

![distributed mode multiple db deployment diagran](./clairv4_distributed_multi_db.png)

In the above diagram a load balancer is configured to route traffic coming from the client to the correct service. This routing is path based routing and requires a layer 7 load balancer. Traefik, Nginx, and HAProxy are all capable of this. As mentioned above this funtionality is native to Openshift and Kubernetes.

In this configuration you'd supply each node type with their own database conn string and inform each node type how to contact their dependent services. Each node will need to have it's mode CLI flag or ENV variable set to the appropriate node type. 
See [Config Reference](../reference/config.md)


```
...
indexer:
    connstring: "host=indexer-clairdb user=pqgotest dbname=pqgotest sslmode=verify-full"
matcher:
    connstring: "host=matcher-clairdb user=pqgotest dbname=pqgotest sslmode=verify-full"
    indexer_addr: "indexer-service"
    ...
notifier:
    connstring: "host=notifier-clairdb user=pqgotest dbname=pqgotest sslmode=verify-full"
    indexer_addr: "indexer-service"
    matcher_addr: "matcher-service"
    ...
```

Keep in mind you do not need a config file per node type. You may provide each node the same config and each node will configure itself correctly, only using the values necessary for their configured mode.

## TLS Termination

Currently ClairV4 punts TLS termination to the load balancing infrastucture. This is a design choice due to the ubiquity of Kubernetes and Openshift infrastructure providing this facility. ClairV4 requires a load balancing solution to terminate TLS.

## More On Path Routing

If you are considering a distributed deployment you will need more details on [path based routing](https://devcentral.f5.com/s/articles/the-three-http-routing-patterns-you-should-know-30764). 

Learn how to grab our OpenAPI spec [here](./api.mw) and either start up a local dev instance of the swagger editor or load the spec file into the [online editor](https://petstore.swagger.io/#/)

You will notice particular API paths are grouped by the services which implement them. This is your guide to configure your layer 7 load balancer correctly. 

When the loadbalancer encounters a particular path prefix it must send those request to the correct set of ClairV4 nodes. 

For example this is how we configure Traefik in our local development environment.
```
"traefik.enable=true"
"traefik.http.routers.notifications.entrypoints=clair"
"traefik.http.routers.notifications.rule=PathPrefix(`/api/v1/notification`)"
"traefik.http.routers.notifications.service=notifications"
"traefik.http.services.notifications.loadbalancer.server.port=6000"
```

This configuration is saying "take any paths prefixes of /api/v1/notification and send them to the notifier services on port 6060"

Every load balancer will have their own way to perform path routing. Check the documentation for your infrastructure of choice.
