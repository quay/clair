package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	plugin "github.com/golang/protobuf/protoc-gen-go/plugin"
	"github.com/grpc-ecosystem/grpc-gateway/codegenerator"
	"github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway/descriptor"
	"github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger/genswagger"
)

var (
	importPrefix    = flag.String("import_prefix", "", "prefix to be added to go package paths for imported proto files")
	file            = flag.String("file", "-", "where to load data from")
	allowDeleteBody = flag.Bool("allow_delete_body", false, "unless set, HTTP DELETE methods may not have a body")
)

func main() {
	flag.Parse()
	defer glog.Flush()

	reg := descriptor.NewRegistry()

	glog.V(1).Info("Processing code generator request")
	f := os.Stdin
	if *file != "-" {
		var err error
		f, err = os.Open(*file)
		if err != nil {
			glog.Fatal(err)
		}
	}
	glog.V(1).Info("Parsing code generator request")
	req, err := codegenerator.ParseRequest(f)
	if err != nil {
		glog.Fatal(err)
	}
	glog.V(1).Info("Parsed code generator request")
	pkgMap := make(map[string]string)
	if req.Parameter != nil {
		err := parseReqParam(req.GetParameter(), flag.CommandLine, pkgMap)
		if err != nil {
			glog.Fatalf("Error parsing flags: %v", err)
		}
	}

	reg.SetPrefix(*importPrefix)
	reg.SetAllowDeleteBody(*allowDeleteBody)
	for k, v := range pkgMap {
		reg.AddPkgMap(k, v)
	}
	g := genswagger.New(reg)

	if err := reg.Load(req); err != nil {
		emitError(err)
		return
	}

	var targets []*descriptor.File
	for _, target := range req.FileToGenerate {
		f, err := reg.LookupFile(target)
		if err != nil {
			glog.Fatal(err)
		}
		targets = append(targets, f)
	}

	out, err := g.Generate(targets)
	glog.V(1).Info("Processed code generator request")
	if err != nil {
		emitError(err)
		return
	}
	emitFiles(out)
}

func emitFiles(out []*plugin.CodeGeneratorResponse_File) {
	emitResp(&plugin.CodeGeneratorResponse{File: out})
}

func emitError(err error) {
	emitResp(&plugin.CodeGeneratorResponse{Error: proto.String(err.Error())})
}

func emitResp(resp *plugin.CodeGeneratorResponse) {
	buf, err := proto.Marshal(resp)
	if err != nil {
		glog.Fatal(err)
	}
	if _, err := os.Stdout.Write(buf); err != nil {
		glog.Fatal(err)
	}
}

// parseReqParam parses a CodeGeneratorRequest parameter and adds the
// extracted values to the given FlagSet and pkgMap. Returns a non-nil
// error if setting a flag failed.
func parseReqParam(param string, f *flag.FlagSet, pkgMap map[string]string) error {
	if param == "" {
		return nil
	}
	for _, p := range strings.Split(param, ",") {
		spec := strings.SplitN(p, "=", 2)
		if len(spec) == 1 {
			if spec[0] == "allow_delete_body" {
				err := f.Set(spec[0], "true")
				if err != nil {
					return fmt.Errorf("Cannot set flag %s: %v", p, err)
				}
				continue
			}
			err := f.Set(spec[0], "")
			if err != nil {
				return fmt.Errorf("Cannot set flag %s: %v", p, err)
			}
			continue
		}
		name, value := spec[0], spec[1]
		if strings.HasPrefix(name, "M") {
			pkgMap[name[1:]] = value
			continue
		}
		if err := f.Set(name, value); err != nil {
			return fmt.Errorf("Cannot set flag %s: %v", p, err)
		}
	}
	return nil
}
