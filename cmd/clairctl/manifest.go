package main

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/quay/claircore"
	"github.com/urfave/cli/v2"
	"golang.org/x/sync/errgroup"

	"github.com/quay/clair/v4/internal/codec"
)

var ManifestCmd = &cli.Command{
	Name:        "manifest",
	Description: "print a clair manifest for the named container",
	Usage:       "print a clair manifest for the named container",
	Action:      manifestAction,
}

func manifestAction(c *cli.Context) error {
	debug.Println("manifest")
	args := c.Args()
	if args.Len() == 0 {
		return errors.New("missing needed arguments")
	}

	result := make(chan *claircore.Manifest)
	done := make(chan struct{})
	eg, ctx := errgroup.WithContext(c.Context)
	go func() {
		defer close(done)
		enc := codec.GetEncoder(os.Stdout)
		defer codec.PutEncoder(enc)
		for m := range result {
			enc.MustEncode(m)
		}
	}()

	for i := 0; i < args.Len(); i++ {
		name := args.Get(i)
		debug.Printf("%s: fetching", name)
		eg.Go(func() error {
			m, err := Inspect(ctx, name)
			if err != nil {
				debug.Printf("%s: err: %v", name, err)
				return err
			}
			debug.Printf("%s: ok", name)
			result <- m
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

func Inspect(ctx context.Context, r string) (*claircore.Manifest, error) {
	rt, err := rt(r)
	if err != nil {
		return nil, err
	}

	ref, err := name.ParseReference(r)
	if err != nil {
		return nil, err
	}
	desc, err := remote.Get(ref, remote.WithTransport(rt))
	if err != nil {
		return nil, err
	}
	img, err := desc.Image()
	if err != nil {
		return nil, err
	}
	dig, err := img.Digest()
	if err != nil {
		return nil, err
	}
	ccd, err := claircore.ParseDigest(dig.String())
	if err != nil {
		return nil, err
	}
	out := claircore.Manifest{Hash: ccd}
	debug.Printf("%s: found manifest %v", r, ccd)

	ls, err := img.Layers()
	if err != nil {
		return nil, err
	}
	debug.Printf("%s: found %d layers", r, len(ls))

	repo := ref.Context()
	rURL := url.URL{
		Scheme: repo.Scheme(),
		Host:   repo.RegistryStr(),
	}
	c := http.Client{
		Transport: rt,
	}

	for _, l := range ls {
		d, err := l.Digest()
		if err != nil {
			return nil, err
		}
		ccd, err := claircore.ParseDigest(d.String())
		if err != nil {
			return nil, err
		}
		u, err := rURL.Parse(path.Join("/", "v2", strings.TrimPrefix(repo.RepositoryStr(), repo.RegistryStr()), "blobs", d.String()))
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
		if err != nil {
			return nil, err
		}
		res, err := c.Do(req)
		if err != nil {
			return nil, err
		}
		res.Body.Close()

		res.Request.Header.Del("User-Agent")
		out.Layers = append(out.Layers, &claircore.Layer{
			Hash:    ccd,
			URI:     res.Request.URL.String(),
			Headers: res.Request.Header,
		})
	}

	return &out, nil
}
