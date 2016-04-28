package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/Sirupsen/logrus"
	"github.com/coreos/clair/cmd/clairctl/clair"
	"github.com/coreos/clair/cmd/clairctl/xstrings"
	"github.com/spf13/viper"
)

var ErrLoginNotFound = errors.New("user is not log in")

type r struct {
	Path, Format string
}
type c struct {
	URI, Priority    string
	Port, HealthPort int
	Report           r
}
type a struct {
	InsecureSkipVerify bool
}
type h struct {
	IP, TempFolder string
	Port           int
}
type config struct {
	Clair      c
	Auth       a
	Hyperclair h
}

// Init reads in config file and ENV variables if set.
func Init(cfgFile string, logLevel string) {
	lvl := logrus.WarnLevel
	if logLevel != "" {
		var err error
		lvl, err = logrus.ParseLevel(logLevel)
		if err != nil {
			logrus.Warningf("Wrong Log level %v, defaults to [Warning]", logLevel)
			lvl = logrus.WarnLevel
		}
	}
	logrus.SetLevel(lvl)

	viper.SetEnvPrefix("hyperclair")
	viper.SetConfigName("hyperclair")        // name of config file (without extension)
	viper.AddConfigPath("$HOME/.hyperclair") // adding home directory as first search path
	viper.AddConfigPath(".")                 // adding home directory as first search path
	viper.AutomaticEnv()                     // read in environment variables that match
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	}
	err := viper.ReadInConfig()
	if err != nil {
		logrus.Debugf("No config file used")
	} else {
		logrus.Debugf("Using config file: %v", viper.ConfigFileUsed())
	}

	if viper.Get("clair.uri") == nil {
		viper.Set("clair.uri", "http://localhost")
	}
	if viper.Get("clair.port") == nil {
		viper.Set("clair.port", "6060")
	}
	if viper.Get("clair.healthPort") == nil {
		viper.Set("clair.healthPort", "6061")
	}
	if viper.Get("clair.priority") == nil {
		viper.Set("clair.priority", "Low")
	}
	if viper.Get("clair.report.path") == nil {
		viper.Set("clair.report.path", "reports")
	}
	if viper.Get("clair.report.format") == nil {
		viper.Set("clair.report.format", "html")
	}
	if viper.Get("auth.insecureSkipVerify") == nil {
		viper.Set("auth.insecureSkipVerify", "true")
	}
	if viper.Get("hyperclair.ip") == nil {
		viper.Set("hyperclair.ip", "")
	}
	if viper.Get("hyperclair.port") == nil {
		viper.Set("hyperclair.port", 0)
	}
	if viper.Get("hyperclair.tempFolder") == nil {
		viper.Set("hyperclair.tempFolder", "/tmp/hyperclair")
	}
	clair.Config()
}

func values() config {
	return config{
		Clair: c{
			URI:        viper.GetString("clair.uri"),
			Port:       viper.GetInt("clair.port"),
			HealthPort: viper.GetInt("clair.healthPort"),
			Priority:   viper.GetString("clair.priority"),
			Report: r{
				Path:   viper.GetString("clair.report.path"),
				Format: viper.GetString("clair.report.format"),
			},
		},
		Auth: a{
			InsecureSkipVerify: viper.GetBool("auth.insecureSkipVerify"),
		},
		Hyperclair: h{
			IP:         viper.GetString("hyperclair.ip"),
			Port:       viper.GetInt("hyperclair.port"),
			TempFolder: viper.GetString("hyperclair.tempFolder"),
		},
	}
}

func Print() {
	cfg := values()
	cfgBytes, err := yaml.Marshal(cfg)
	if err != nil {
		logrus.Fatalf("marshalling configuration: %v", err)
	}

	fmt.Println("Configuration")
	fmt.Printf("%v", string(cfgBytes))
}

func HyperclairHome() string {
	usr, err := user.Current()
	if err != nil {
		panic(err)
	}
	p := usr.HomeDir + "/.hyperclair"

	if _, err := os.Stat(p); os.IsNotExist(err) {
		os.Mkdir(p, 0700)
	}
	return p
}

type Login struct {
	Username string
	Password string
}

type loginMapping map[string]Login

func HyperclairConfig() string {
	return HyperclairHome() + "/config.json"
}

func AddLogin(registry string, login Login) error {
	var logins loginMapping

	if err := readConfigFile(&logins, HyperclairConfig()); err != nil {
		return fmt.Errorf("reading hyperclair file: %v", err)
	}

	logins[registry] = login

	if err := writeConfigFile(logins, HyperclairConfig()); err != nil {
		return fmt.Errorf("indenting login: %v", err)
	}

	return nil
}
func GetLogin(registry string) (Login, error) {
	if _, err := os.Stat(HyperclairConfig()); err == nil {
		var logins loginMapping

		if err := readConfigFile(&logins, HyperclairConfig()); err != nil {
			return Login{}, fmt.Errorf("reading hyperclair file: %v", err)
		}

		if login, present := logins[registry]; present {
			d, err := base64.StdEncoding.DecodeString(login.Password)
			if err != nil {
				return Login{}, fmt.Errorf("decoding password: %v", err)
			}
			login.Password = string(d)
			return login, nil
		}
	}
	return Login{}, ErrLoginNotFound
}

func RemoveLogin(registry string) (bool, error) {
	if _, err := os.Stat(HyperclairConfig()); err == nil {
		var logins loginMapping

		if err := readConfigFile(&logins, HyperclairConfig()); err != nil {
			return false, fmt.Errorf("reading hyperclair file: %v", err)
		}

		if _, present := logins[registry]; present {
			delete(logins, registry)

			if err := writeConfigFile(logins, HyperclairConfig()); err != nil {
				return false, fmt.Errorf("indenting login: %v", err)
			}

			return true, nil
		}
	}
	return false, nil
}

func readConfigFile(logins *loginMapping, file string) error {
	if _, err := os.Stat(file); err == nil {
		f, err := ioutil.ReadFile(file)
		if err != nil {
			return err
		}

		if err := json.Unmarshal(f, &logins); err != nil {
			return err
		}
	} else {
		*logins = loginMapping{}
	}
	return nil
}

func writeConfigFile(logins loginMapping, file string) error {
	s, err := xstrings.ToIndentJSON(logins)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(file, s, os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}

//LocalServerIP return the local hyperclair server IP
func LocalServerIP() (string, error) {
	localPort := viper.GetString("hyperclair.port")
	localIP := viper.GetString("hyperclair.ip")
	if localIP == "" {
		logrus.Infoln("retrieving docker0 interface as local IP")
		var err error
		localIP, err = Docker0InterfaceIP()
		if err != nil {
			return "", fmt.Errorf("retrieving docker0 interface ip: %v", err)
		}
	}
	return strings.TrimSpace(localIP) + ":" + localPort, nil
}

//Docker0InterfaceIP return the docker0 interface ip by running `ip route show | grep docker0 | awk {print $9}`
func Docker0InterfaceIP() (string, error) {
	var localIP bytes.Buffer

	ip := exec.Command("ip", "route", "show")
	rGrep, wIP := io.Pipe()
	grep := exec.Command("grep", "docker0")
	ip.Stdout = wIP
	grep.Stdin = rGrep
	awk := exec.Command("awk", "{print $9}")
	rAwk, wGrep := io.Pipe()
	grep.Stdout = wGrep
	awk.Stdin = rAwk
	awk.Stdout = &localIP
	err := ip.Start()
	if err != nil {
		return "", err
	}
	err = grep.Start()
	if err != nil {
		return "", err
	}
	err = awk.Start()
	if err != nil {
		return "", err
	}
	err = ip.Wait()
	if err != nil {
		return "", err
	}
	err = wIP.Close()
	if err != nil {
		return "", err
	}
	err = grep.Wait()
	if err != nil {
		return "", err
	}
	err = wGrep.Close()
	if err != nil {
		return "", err
	}
	err = awk.Wait()
	if err != nil {
		return "", err
	}
	return localIP.String(), nil
}
