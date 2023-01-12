package main

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/quay/claircore"
	"github.com/quay/zlog"
	"github.com/urfave/cli/v2"
	"golang.org/x/sync/errgroup"

	"github.com/quay/clair/v4/internal/codec"
	"github.com/quay/clair/v4/internal/httputil"
)

// ReportCmd is the "report" subcommand.
var ReportCmd = &cli.Command{
	Name:        "report",
	Description: "Request and print a Clair vulnerability report for the named container(s).",
	Action:      reportAction,
	Usage:       "request vulnerability reports for the named containers",
	ArgsUsage:   "container...",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "host",
			Usage:   "URL for the clairv4 v1 API.",
			Value:   "http://localhost:6060/",
			EnvVars: []string{"CLAIR_API"},
		},
		&cli.GenericFlag{
			Name:        "out",
			Aliases:     []string{"o"},
			Usage:       "output format: text, json, xml",
			DefaultText: "text",
			Value:       &outFmt{},
		},
		&cli.BoolFlag{
			Name:    "keep-going",
			Aliases: []string{"k"},
			Usage:   "when requesting more than one report, don't stop at the first error reported",
			Value:   false,
		},
		&cli.BoolFlag{
			Name:  "novel",
			Usage: "only upload novel manifests",
			Value: false,
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

func (o *outFmt) Formatter(ctx context.Context, w io.WriteCloser) Formatter {
	switch o.fmt {
	case "", "text":
		zlog.Debug(ctx).Msg("using text output")
		r, err := newTextFormatter(w)
		if err != nil {
			panic(err)
		}
		return r
	case "json":
		zlog.Debug(ctx).Msg("using json output")
		return &jsonFormatter{
			enc: codec.GetEncoder(w),
			c:   w,
		}
	case "xml":
		zlog.Debug(ctx).Msg("using xml output")
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
	Report *claircore.VulnerabilityReport
	Err    error
	Name   string
}

func reportAction(c *cli.Context) error {
	args := c.Args()
	if args.Len() == 0 {
		return errors.New("missing needed arguments")
	}

	// Do we have a config?
	fi, err := os.Stat(c.Path("config"))
	useCfg := err == nil && !fi.IsDir()
	ctx := c.Context
	hc, err := httputil.NewClient(ctx, false)
	if err != nil {
		return err
	}

	var s *httputil.Signer
	if useCfg {
		cfg, err := loadConfig(c.Path("config"))
		if err != nil {
			return err
		}
		s, err = httputil.NewSigner(ctx, cfg, commonClaim)
		if err != nil {
			return err
		}
		if err = s.Add(ctx, c.String("host")); err != nil {
			return err
		}
	}
	cc, err := NewClient(hc, c.String("host"), s)
	if err != nil {
		return err
	}

	result := make(chan *Result)
	done := make(chan struct{})
	keepgoing := c.Bool("keep-going") && args.Len() > 1
	eg, ctx := errgroup.WithContext(c.Context)
	go func() {
		defer close(done)
		out := c.Generic("out").(*outFmt)
		f := out.Formatter(ctx, os.Stdout)
		defer f.Close()
		for r := range result {
			if err := f.Format(r); err != nil {
				log.Println(err)
			}
		}
	}()

	for i := 0; i < args.Len(); i++ {
		ref := args.Get(i)
		ctx := zlog.ContextWithValues(ctx, "ref", ref)
		zlog.Debug(ctx).
			Msg("fetching")
		eg.Go(func() error {
			d, err := resolveRef(ctx, ref)
			if err != nil {
				zlog.Debug(ctx).
					Err(err).
					Send()
				return err
			}
			ctx := zlog.ContextWithValues(ctx, "digest", d.String())
			zlog.Debug(ctx).
				Msg("found manifest")

			// This bit is tricky:
			//
			// Initially start with a nil manifest, which optimistically
			// prevents us from generating one.
			//
			// If we need the manifest, populate the manifest and jump to Again.
			var m *claircore.Manifest
			ct := 1
		Again:
			if ct > 20 {
				return errors.New("too many attempts")
			}
			zlog.Debug(ctx).
				Int("attempt", ct).
				Msg("requesting index_report")
			err = cc.IndexReport(ctx, d, m)
			switch {
			case err == nil:
			case errors.Is(err, errNeedManifest):
				if c.Bool("novel") {
					zlog.Debug(ctx).
						Msg("manifest already known, skipping upload")
					break
				}
				fallthrough
			case errors.Is(err, errNovelManifest):
				m, err = Inspect(ctx, ref)
				if err != nil {
					zlog.Debug(ctx).
						Err(err).
						Msg("manifest error")
					if keepgoing {
						zlog.Info(ctx).
							Err(err).
							Msg("ignoring manifest error")
						return nil
					}
					return err
				}
				ct++
				goto Again
			default:
				zlog.Debug(ctx).
					Err(err).
					Msg("index error")
				if keepgoing {
					return nil
				}
				return err
			}

			r := Result{
				Name: ref,
			}
			r.Report, r.Err = cc.VulnerabilityReport(ctx, d)
			if r.Err != nil {
				r.Err = fmt.Errorf("%s(%v): %w", ref, d, r.Err)
			}
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

func resolveRef(ctx context.Context, r string) (claircore.Digest, error) {
	var d claircore.Digest
	rt, err := rt(ctx, r)
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
