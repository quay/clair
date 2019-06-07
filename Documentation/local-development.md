# Local Development

# Requirements

* Docker CLI
* Kubernetes (minikube or docker desktop)
* Helm 

# Overview 

The local development environment is driven by a Makefile in the root of this repository. 
This Makefile is responsible for building a Clair container on the local Kubernetes instances and deploying said container.
In order to build the container the Docker CLI tools are expected to be present.
In order to deploy the container the Helm CLI tool is expected to be present and the local Kubernetes cluster **must** be running Tiller. 

We expect you to be running either minikube or docker desktop with the optional Kubernetes cluster deployed. 

# Usage

### Deploy

Ensure that Tiller is running on your Kubernetes cluster. Usually this is accomplished by simply running `helm init`.
If you experience any issues ensure that `kubectl config current-context` points to the local Kubernetes cluster.
The Tiller installation takes a few seconds. You can check the status via the helm CLI to confirm it has finished it's deployment.

At the root of this repository run the command `make deploy-local`. 
This command will push the docker build context to the local Kubernetes's docker daemon where it will be built then deploy a postgres and Clair image.
This command is also designed to be ran idempotently.
When you have made changes to the code in the working directory simply run `make deploy-local` to deploy these changes.
The database will remain over subsequent issues of this make target. 

### Teardown

When you are finished developing and would like to tear down the environment the command `make teardown-local` may be used.
This command removes both the current Clair instance along with the postgres database.
Run this command only when you are willing to remove all the CVE data from your local development environment.

# Interacting with Clair and Postgres

Clair and the associated postgres instance are launched as pods on the local kubernetes cluster. 
In order to interact with these two applications you may use the `kubectl port-forward` command to forward the associated k8 service port to a port on `localhost`.

For example:
```
❯ kubectl port-forward clair-669775b7c7-hhf46 6060:6060 6061:6061
Forwarding from 127.0.0.1:6060 -> 6060
Forwarding from [::1]:6060 -> 6060
Forwarding from 127.0.0.1:6061 -> 6061
Forwarding from [::1]:6061 -> 6061

❯ kubectl port-forward clair-pg-postgresql-0 5432:5432
Forwarding from 127.0.0.1:5432 -> 5432
Forwarding from [::1]:5432 -> 5432
```

# Caveats

Due to the make targets being idempotent you may see errors which do not necessarily mean something went wrong.
Reference the `Makefile` at the root of this repository and make note of any lines prefixed with a `-` to understand which commands are allowed to fail.

