# Authentication

Previous versions of Clair used [jwtproxy] to gate authentication. For ease of
building and deployment, v4 handles authentication itself.

Authentication is configured by specifying configuration objects underneath the
`auth` key of the configuration. Multiple authentication configurations may be
present, but they will be used preferentially in the order laid out below.

[jwtproxy]: https://github.com/quay/jwtproxy

### PSK

Clair implements JWT-based authentication using a pre-shared key.

#### Configuration

The `auth` stanza of the configuration file requires two parameters: `iss`, which
is the issuer to validate on all incoming requests; and `key`, which is a base64
encoded symmetric key for validating the requests.

```yaml
auth:
  psk:
    key: >-
      MDQ4ODBlNDAtNDc0ZC00MWUxLThhMzAtOTk0MzEwMGQwYTMxCg==
    iss: 'issuer'
```

