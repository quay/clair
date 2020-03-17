package main

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/quay/claircore"
	"github.com/urfave/cli/v2"
	"golang.org/x/sync/errgroup"
)

// ReportCmd is the "report" subcommand.
var ReportCmd = &cli.Command{
	Name:        "report",
	Description: "Request and print a Clair vulnerability report for the provided container(s).",
	Action:      reportAction,
	Usage:       "request vulnerability reports for the named containers",
	ArgsUsage:   "container...",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "api",
			Usage: "URL for the clairv4 v1 API.",
			Value: "http://localhost:6060/api/v1/",
		},
		&cli.GenericFlag{
			Name:        "out",
			Aliases:     []string{"o"},
			Usage:       "output format: text, json, xml",
			DefaultText: "text",
			Value:       &outFmt{},
		},
	},
}

// OutFmt is a flag that creates a Formatter for us.
type outFmt struct {
	fmt string
}

func (o *outFmt) Set(v string) error {
	switch v {
	case "text":
	case "json":
	case "xml":
	default:
		return fmt.Errorf("unrecognized output format %q", v)
	}
	o.fmt = v
	return nil
}

func (o *outFmt) String() string {
	return o.fmt
}

func (o *outFmt) Formatter(w io.WriteCloser) Formatter {
	switch o.fmt {
	case "", "text":
		debug.Println("using text output")
		r, err := newTextFormatter(w)
		if err != nil {
			panic(err)
		}
		return r
	case "json":
		debug.Println("using json output")
		return &jsonFormatter{
			enc:    json.NewEncoder(w),
			Closer: w,
		}
	case "xml":
		debug.Println("using xml output")
		return &xmlFormatter{
			enc: xml.NewEncoder(w),
			c:   w,
		}
	default:
	}
	panic("unreachable") // Somehow dodged the initial Set call.
}

// Formatter is the common interface for presenting results.
type Formatter interface {
	Format(*Result) error
	io.Closer
}

// Result is the result of a Clair request flow.
//
// Users should examine Err first to determine if the request succeeded.
type Result struct {
	Name   string
	Err    error
	Report *claircore.VulnerabilityReport
}

func reportAction(c *cli.Context) error {
	args := c.Args()
	if args.Len() == 0 {
		return errors.New("missing needed arguments")
	}

	cc, err := NewClient(c.String("api"))
	if err != nil {
		return err
	}

	result := make(chan *Result)
	done := make(chan struct{})
	eg, ctx := errgroup.WithContext(c.Context)
	go func() {
		defer close(done)
		out := c.Generic("out").(*outFmt)
		f := out.Formatter(os.Stdout)
		defer f.Close()
		for r := range result {
			if err := f.Format(r); err != nil {
				log.Println(err)
			}
		}
	}()

	for i := 0; i < args.Len(); i++ {
		ref := args.Get(i)
		debug.Printf("%s: fetching", ref)
		eg.Go(func() error {
			d, err := resolveRef(ref)
			if err != nil {
				debug.Printf("%s: error: %v", ref, err)
				return err
			}
			debug.Printf("%s: manifest: %v", ref, d)

			// This bit is tricky:
			//
			// Initially start with a nil manifest, which optimistically
			// prevents us from generating one.
			//
			// If we need the manifest, populate the manifest and jump to Again.
			var m *claircore.Manifest
		Again:
			err = cc.IndexReport(ctx, d, m)
			switch {
			case err == nil:
			case errors.Is(err, errNeedManifest):
				m, err = Inspect(ctx, ref)
				if err != nil {
					debug.Printf("%s: manifest error: %v", ref, err)
					return err
				}
				goto Again
			default:
				debug.Printf("%s: index error: %v", ref, err)
				return err
			}

			r := Result{
				Name: ref,
			}
			r.Report, r.Err = cc.VulnerabilityReport(ctx, d)
			result <- &r
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return err
	}
	close(result)
	<-done
	return nil

}

func resolveRef(r string) (claircore.Digest, error) {
	var d claircore.Digest
	rt, err := rt(r)
	if err != nil {
		return d, err
	}

	ref, err := name.ParseReference(r)
	if err != nil {
		return d, err
	}
	desc, err := remote.Get(ref, remote.WithTransport(rt))
	if err != nil {
		return d, err
	}
	img, err := desc.Image()
	if err != nil {
		return d, err
	}
	dig, err := img.Digest()
	if err != nil {
		return d, err
	}
	return claircore.ParseDigest(dig.String())
}
