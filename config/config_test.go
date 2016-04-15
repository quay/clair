package config

import (
	"io/ioutil"
	"log"
	"os"
	"testing"

	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/stretchr/testify/assert"
)

const wrongConfig = `
dummyKey:
    wrong:true
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

	assert.EqualError(t, err, cerrors.ErrConfigNotLoaded.Error())
}

func TestLoad(t *testing.T) {
	_, err := Load("../config.example.yaml")
	assert.NoError(t, err)
}
