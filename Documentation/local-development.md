# Local Development

# Requirements

* Docker cli
* Kubernetes (minikube or docker desktop)
* Helm 

# Overview 

The local development environment is driven by a Makefile in the root of this repository. 
This Makefile is responsible for building a clair container on the local kubernetes instances and deploying said container.
In order to build the container the Docker cli tools are expected to be present.
In order to deploy the container the Helm cli tool is expected to be present and the local kubernetes cluster **must** be running tiller. 

We expect you to be running either minikube or docker desktop with the optional kubernetes cluster deployed. 

# Usage

### Deploy

Ensure that tiller is running on your kubernetes cluster. Usually this is accomplished by simply running `helm init`.
If you experience any issues ensure that `kubectl config current-context` points to the local kubernetes cluster.
The tiller installation takes a few seconds. You can check the status via the helm cli to confirm it has finished it's deployment.

At the root of this repository run the command `make deploy-local`. 
This command will push the docker build context to the local kubernetes's docker daemon where it will be built then deploy a postgres and clair image.
This command is also designed to be ran idempotently.
When you have made changes to the code in the working directory simply run `make deploy-local` to deploy these changes.
The database will remain over subsequent issues of this make target. 

### Teardown

When you are finished developing and would like to tear down the environment the command `make teardown-local` may be used.
This command removes both the current clair instance along with the postgres database.
Run this command only when you are willing to remove all the CVE data from your local development environment.

# Caveats

Due to the make targets being idempotent you may see errors which do not necessarily mean something went wrong.
Reference the `Makefile` at the root of this repository and make note of any lines prefixed with a `-` to understand which commands are allowed to fail.

