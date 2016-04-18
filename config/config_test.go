package config

import (
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

const wrongConfig = `
dummyKey:
    wrong:true
`

const goodConfig = `
clair:
  database:
    source: postgresql://postgres:root@postgres:5432?sslmode=disable
    cacheSize: 16384
  api:
    port: 6060
    healthport: 6061
    timeout: 900s
    paginationKey:
    servername:
    cafile:
    keyfile:
    certfile:
  updater:
    interval: 2h
  notifier:
    attempts: 3
    renotifyInterval: 2h
    http:
      endpoint:
      servername:
      cafile:
      keyfile:
      certfile:
      proxy:
`

func TestLoadWrongConfiguration(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "clair-config")
	if err != nil {
		log.Fatal(err)
	}

	defer os.Remove(tmpfile.Name()) // clean up
	if _, err := tmpfile.Write([]byte(wrongConfig)); err != nil {
		log.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		log.Fatal(err)
	}

	_, err = Load(tmpfile.Name())

	assert.EqualError(t, err, ErrDatasourceNotLoaded.Error())
}

func TestLoad(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "clair-config")
	if err != nil {
		log.Fatal(err)
	}

	defer os.Remove(tmpfile.Name()) // clean up

	if _, err := tmpfile.Write([]byte(goodConfig)); err != nil {
		log.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		log.Fatal(err)
	}

	_, err = Load(tmpfile.Name())
	assert.NoError(t, err)
}
