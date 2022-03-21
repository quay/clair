// Package config is the configuration package for Clair's binaries. See the
// Config type for the main entry point.
//
// It's currently meant for reading configs and tested against YAML and JSON.
package config

// This pakcage can't use "omitempty" tags on slices because "not present" and
// "empty" aren't distinguished. This would be much easier if code didn't
// serialize our config struct. It's impossible to implement custom YAML
// marshalling without importing the yaml.v3 package.
