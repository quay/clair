# Security

# Enabling HTTPS on the API

HTTPS provides clients the ability to verify the server identity and provide transport security.

For this you need your CA certificate (ca.crt) and signed key pair (server.crt, server.key) ready.
To enable it, provide the signed key pair files in the configuration under `api/keyfile` and `api/certfile` keys.

To test it, you want to use curl like this:

	curl --cacert ca.crt -L https://127.0.0.1:6060/v1/versions

You should be able to see the handshake succeed. Because we use self-signed certificates with our own certificate authorities you need to provide the CA to curl using the --cacert option. Another possibility would be to add your CA certificate to the trusted certificates on your system (usually in /etc/ssl/certs).

**OSX 10.9+ Users**: curl 7.30.0 on OSX 10.9+ doesn't understand certificates passed in on the command line. Instead you must import the dummy ca.crt directly into the keychain or add the -k flag to curl to ignore errors. If you want to test without the -k flag run open ca.crt and follow the prompts. Please remove this certificate after you are done testing!

# Enabling Client Certificate Auth on the API

We can also use client certificates to prevent unauthorized access to the API.

The clients will provide their certificates to the server and the server will check whether the cert is signed by the supplied CA and decide whether to serve the request.

You need the same files mentioned in the HTTPS section, as well as a key pair for the client (client.crt, client.key) signed by the same certificate authority. To enable it, use the same configuration as above for HTTPS and the additional `api/cafile` key parameter with the CA certificate path.

The test command from the HTTPS section should be rejected, instead we need to provide the client key pair:

    curl --cacert ca.crt --cert client.crt --key client.key -L https://127.0.0.1:6060/v1/versions

**OSX 10.10+ Users**: A bundle in P12 (PKCS#12) format must be used. To convert your key pair, the following command should be used, in which the password is mandatory. Then, `--cert client.p12` along with `--password pass` replace `--cert client.crt --key client.key`. You may also import the P12 certificate into your Keychain and specify its name as it appears in the Keychain instead of the path to the file.

    openssl pkcs12 -export -in client.crt -inkey client1.key -out certs/client.p12 -password pass:pass

# Generating self-signed certificates
[etcd-ca](https://github.com/coreos/etcd-ca) is a great tool when it comes to easily generate certificates. Below is an example to generate a new CA, server and client key pairs, inspired by their example.

```
git clone https://github.com/coreos/etcd-ca
cd etcd-ca
./build

# Create CA
./bin/etcd-ca init
./bin/etcd-ca export | tar xvf -

# Create certificate for server
./bin/etcd-ca new-cert --passphrase $passphrase --ip $server1ip --domain $server1hostname server1
./bin/etcd-ca sign --passphrase $passphrase server1
./bin/etcd-ca export --insecure --passphrase $passphrase server1 | tar xvf -

# Create certificate for client
./bin/etcd-ca new-cert --passphrase $passphrase client1
./bin/etcd-ca sign --passphrase $passphrase client1
./bin/etcd-ca export --insecure --passphrase $passphrase client1 | tar xvf -
```
