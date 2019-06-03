local pipeline(goVersion, postgresVersion) = {
  kind: 'pipeline',
  name: 'go-' + goVersion + '-postgres' + postgresVersion,
  workspace: {
    base: '/go',
    path: 'src/github.com/coreos/clair',
  },
  clone: { depth: 50 },

  services: [{
    name: 'postgres',
    image: 'postgres:' + postgresVersion + '-alpine',
    ports: [5432],
  }],

  steps: [
    {
      name: 'compile',
      image: 'golang:' + goVersion + '-alpine',
      commands: [
        'apk add --no-cache build-base git rpm xz',
        'make build',
      ],
    },
    {
      name: 'unit tests',
      image: 'golang:' + goVersion + '-alpine',
      commands: [
        'apk add --no-cache build-base git rpm xz',
        'git config --global user.name "Test"',
        'git config --global user.email "test@coreos.com"',
        'make unit-test',
      ],
    },
    {
      name: 'db tests',
      image: 'golang:' + goVersion + '-alpine',
      commands: [
        'apk add --no-cache build-base git rpm xz',
        'make db-test',
      ],
      environment: { CLAIR_TEST_PGSQL: 'postgres@postgres:5432' },
    },
  ],
};

[
  pipeline('1.12', '9'),
  pipeline('1.12', '10'),
  pipeline('1.12', '11'),
]
