package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/quay/clair/config"
	"github.com/quay/clair/v4/cmd"
)

const (
	envConfig = `CLAIR_CONF`
	envMode   = `CLAIR_MODE`
)

// Flags holds parsed values from command-line flags.
type Flags struct {
	Mode       *config.Mode
	Config     *config.Config
	CPUProfile string
	MemProfile string
}

// Parse parses the provide slice of strings.
func (f *Flags) Parse(argv []string) error {
	set := flag.NewFlagSet("clair", flag.ContinueOnError)
	set.Func("conf", "The file system path to Clair's config file.", f.loadConfig)
	set.Func("mode", "The operation mode for this server, will default to combo.", f.parseMode)
	set.StringVar(&f.CPUProfile, "cpuprofile", "", "Write cpu profile to `file`.")
	set.StringVar(&f.MemProfile, "memprofile", "", "Write memory profile to `file`.")

	if err := set.Parse(argv); err != nil {
		return err
	}

	var errs []error
	set.VisitAll(func(fl *flag.Flag) {
		var key string
		var isSet bool
		var doSet func(string) error
		switch fl.Name {
		case "conf":
			key = envConfig
			isSet = f.Config != nil
			doSet = f.loadConfig
		case "mode":
			key = envMode
			isSet = f.Mode != nil
			doSet = f.parseMode
		default:
			// No special handling.
			return
		}
		if isSet {
			// Flag was already used, no need to look at the environment.
			return
		}
		if v, ok := os.LookupEnv(key); ok {
			if err := doSet(v); err != nil {
				errs = append(errs, err)
			}
			return
		}
		errs = append(errs,
			fmt.Errorf("missing flag %q or environment variable %q", "-"+fl.Name, key))
	})
	if err := errors.Join(errs...); err != nil {
		return err
	}

	f.Config.Mode = *f.Mode
	return nil
}

func (f *Flags) loadConfig(arg string) error {
	var cfg config.Config
	if err := cmd.LoadConfig(&cfg, arg, true); err != nil {
		return err
	}
	f.Config = &cfg
	return nil
}

func (f *Flags) parseMode(arg string) error {
	m, err := config.ParseMode(arg)
	if err != nil {
		return err
	}
	f.Mode = &m
	return nil
}

// SetupCPUProfile sets up CPU profiling, if asked for.
func (f *Flags) SetupCPUProfile() (func(), error) {
	if f.CPUProfile == "" {
		return noop, nil
	}

	w, err := os.Create(f.CPUProfile)
	if err != nil {
		return nil, err
	}
	if err := pprof.StartCPUProfile(w); err != nil {
		return nil, errors.Join(err, w.Close())
	}

	return func() {
		pprof.StopCPUProfile()
		if err := w.Close(); err != nil {
			slog.Error("could not close cpu profile", "reason", err)
		}
	}, nil
}

// SetupMemProfile sets up memory profiling, if asked for.
func (f *Flags) SetupMemProfile() (func(), error) {
	if f.MemProfile == "" {
		return noop, nil
	}

	w, err := os.Create(f.MemProfile)
	if err != nil {
		return nil, err
	}

	return func() {
		runtime.GC() // get up-to-date statistics
		if err := pprof.Lookup("allocs").WriteTo(w, 0); err != nil {
			slog.Error("could not write memory profile", "reason", err)
		}
		if err := w.Close(); err != nil {
			slog.Error("could not close memory profile", "reason", err)
		}
	}, nil
}

func noop() {}
