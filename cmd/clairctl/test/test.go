package test

import (
	"io/ioutil"
	"log"
	"os"
)

func CreateTmpConfigFile(content string) string {

	c := []byte(content)
	tmpfile, err := ioutil.TempFile("", "test-hyperclair")
	if err != nil {
		log.Fatal(err)
	}
	if content != "" {
		if _, err := tmpfile.Write(c); err != nil {
			log.Fatal(err)
		}
		if err := tmpfile.Close(); err != nil {
			log.Fatal(err)
		}
	} else {
		if err := os.Remove(tmpfile.Name()); err != nil {
			log.Fatal(err)
		}
	}
	return tmpfile.Name()
}

func CreateConfigFile(content string, name string, path string) string {
	if err := ioutil.WriteFile(path+"/"+name, []byte(content), 0600); err != nil {
		log.Fatal(err)
	}
	return path + "/" + name
}
