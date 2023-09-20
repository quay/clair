// Package config is the configuration package for Clair's binaries. See the
// [Config] type for the main entry point.
//
// It's currently meant for reading configurations and tested against YAML and
// JSON.
//
// # Version Scheme
//
// This package uses an idiosyncratic versioning scheme:
//
//   - The major version tracks the input format.
//   - The minor version tracks the Go source API.
//   - The patch version increases with fixes and additions.
//
// This means that any valid configuration accepted by `v1.0.0` should continue
// to be accepted for all revisions of the v1 module, but `v1.1.0` may force
// changes on a program importing the module.
package config

// This package can't use "omitempty" tags on slices because "not present" and
// "empty" aren't distinguished. This would be much easier if code didn't
// serialize our config struct. It's impossible to implement custom YAML
// marshalling without importing the yaml.v3 package.
