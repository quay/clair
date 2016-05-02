CONTRIBUTION
-----------------

# Running full dev environnement

```bash
# Running Authentication server, Registry, Clair , Hyperclair-server and Hyperclair-DEV-BOX
docker-compose up -d

# Enter the hyperclair dev box
docker exec -ti hyperclair_dev bash

# Run Any command ex:
go run main.go help
# Or
go run main.go pull registry:5000/wemanity-belgium/ubuntu-git
```
