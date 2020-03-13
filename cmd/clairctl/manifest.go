package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/quay/claircore"
	"github.com/urfave/cli/v2"
	"golang.org/x/sync/errgroup"
)

var ManifestCmd = &cli.Command{
	Name:        "manifest",
	Description: "print a clair manifest for the provided container",
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
		buf := bufio.NewWriter(os.Stdout)
		defer buf.Flush()
		enc := json.NewEncoder(buf)
		for m := range result {
			enc.Encode(m)
			buf.Flush()
		}
	}()

	for i := 0; i < args.Len(); i++ {
		name := args.Get(i)
		debug.Printf("%s: fetching", name)
		eg.Go(func() error {
			m, err := Inspect(ctx, name)
			if err != nil {
				debug.Printf("%s: err: %v", name)
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
	ref, err := name.ParseReference(r)
	if err != nil {
		return nil, err
	}
	repo := ref.Context()
	auth, err := authn.DefaultKeychain.Resolve(repo)
	if err != nil {
		return nil, err
	}
	rt, err := transport.New(repo.Registry, auth, http.DefaultTransport, []string{repo.Scope("pull")})
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

	h, err := img.Digest()
	if err != nil {
		return nil, err
	}
	ccd, err := claircore.ParseDigest(h.String())
	if err != nil {
		return nil, err
	}
	out := claircore.Manifest{
		Hash: ccd,
	}
	debug.Printf("%s: found manifest %v", r, ccd)

	ls, err := img.Layers()
	if err != nil {
		return nil, err
	}
	debug.Printf("%s: found %d layers", r, len(ls))

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
