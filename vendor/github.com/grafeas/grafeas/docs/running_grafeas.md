# Running Grafeas

## Start Grafeas

To start the server go to `samples/server/go-server/api/server/main` and execute

    go run main.go

This will start the Grafeas gRPC and REST API:s on `localhost:8080`. To start grafeas with a custom configuration use the `-config` flag (e.g. `-config config.yaml`). The root directory includes a `config.yaml.sample` that can be used as a starting point when creating your own config file.

### Access REST API with curl

Grafeas provides both a REST API and a gRPC API. Here is an example of using the REST API to list projects in Grafeas.

`curl http://localhost:8080/v1alpha1/projects`

### Access gRPC API with a go client

Below is a small example of a go client that connects to grafeas and outputs any notes in `myproject`

```
package main

import (
	"context"
	"log"

	pb "github.com/grafeas/grafeas/v1alpha1/proto"
	"google.golang.org/grpc"
)

func main() {
	conn, err := grpc.Dial("localhost:8080", grpc.WithInsecure())
	defer conn.Close()
	client := pb.NewGrafeasClient(conn)
	// List notes
	resp, err := client.ListNotes(context.Background(),
		&pb.ListNotesRequest{
			Parent: "projects/myproject",
		})
	if err != nil {
		log.Fatal(err)
	}

	if len(resp.Notes) != 0 {
		log.Println(resp.Notes)
	} else {
		log.Println("Project does not contain any notes")
	}
}
```

## Use Grafeas with self-signed certificate

### Generate CA, keys and certs

_NOTE: The steps described in this section is meant for development environments._

```
# Create CA
openssl genrsa -out ca.key 2048
# make sure to set Common Name to your domain, e.g. localhost (without port)
openssl req -new -x509 -days 365 -key ca.key -out ca.crt

# Create the Client Key and CSR
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr

# Create self-signed client cert
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out client.crt

# Convert Client Key to PKCS
openssl pkcs12 -export -clcerts -in client.crt -inkey client.key -out client.p12

# Convert Client Key to (combined) PEM
openssl pkcs12 -in client.p12 -out client.pem -clcerts
```

This is basically following https://gist.github.com/mtigas/952344 with some tweaks

### Update config

Add the following to your config file

    cafile: ca.crt
    keyfile: ca.key
    certfile: ca.crt

### Access REST API with curl

When using curl with a self signed certificate you need to add `-k/--insecure` and specify the client certificate.

`curl -k --cert path/to/client.pem https://localhost:8080/v1alpha1/projects`

### Access gRPC with a go client

When using a go client to access Grafeas with a self signed certificate you need to specify the client certificate, client key and the CA certificate.

```
package main

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"

	pb "github.com/grafeas/grafeas/v1alpha1/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	certFile = "/path/to/client.crt"
	keyFile  = "/path/to/client.key"
	caFile   = "/path/to/ca.crt"
)

func main() {
	// Load client cert
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal(err)
	}

	// Load CA cert
	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	tlsConfig.BuildNameToCertificate()
	creds := credentials.NewTLS(tlsConfig)
	conn, err := grpc.Dial("localhost:8080", grpc.WithTransportCredentials(creds))
	client := pb.NewGrafeasClient(conn)

	// List notes
	resp, err := client.ListNotes(context.Background(),
		&pb.ListNotesRequest{
			Parent: "projects/myproject",
		})
	if err != nil {
		log.Fatal(err)
	}

	if len(resp.Notes) != 0 {
		log.Println(resp.Notes)
	} else {
		log.Println("Project does not contain any notes")
	}
}
```

## Enable CORS on the sample server.

### Update config

Add the following to your config file below the `api` key.

    cors_allowed_origins:
       - "https://some.example.tld"
       - "https://*.example.net"
