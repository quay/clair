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
	"github.com/quay/zlog"
	"github.com/urfave/cli/v2"
	"golang.org/x/sync/errgroup"

	"github.com/quay/clair/v4/internal/codec"
	"github.com/quay/clair/v4/internal/httputil"
)

var ManifestCmd = &cli.Command{
	Name:        "manifest",
	Description: "print a clair manifest for the named container",
	Usage:       "print a clair manifest for the named container",
	Action:      manifestAction,
}

func manifestAction(c *cli.Context) error {
	ctx := c.Context
	zlog.Debug(ctx).Msg("manifest")
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
		zlog.Debug(ctx).Str("name", name).Msg("fetching")
		eg.Go(func() error {
			m, err := Inspect(ctx, name)
			if err != nil {
				zlog.Debug(ctx).
					Str("name", name).
					Err(err).
					Send()
				return err
			}
			zlog.Debug(ctx).
				Str("name", name).
				Msg("ok")
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
	rt, err := rt(ctx, r)
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
	zlog.Debug(ctx).
		Str("ref", r).
		Stringer("digest", ccd).
		Msg("found manifest")

	ls, err := img.Layers()
	if err != nil {
		return nil, err
	}
	zlog.Debug(ctx).
		Str("ref", r).
		Int("count", len(ls)).
		Msg("found layers")

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
		req, err := httputil.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		// The request is needed to follow any redirection chain that the server sends to a client,
		// but the actual body is not needed when generating a manifest.
		// The Range HTTP header allows us to send the request and get a response mostly for free.
		req.Header.Add("Range", "bytes=0-0")
		res, err := c.Do(req)
		if err != nil {
			return nil, err
		}
		res.Body.Close()
		if res.StatusCode != http.StatusPartialContent {
			zlog.Warn(ctx).
				Int("statuscode", res.StatusCode).
				Int("len", int(res.ContentLength)).
				Str("url", u.String()).
				Msg("server might not support requests with Range HTTP header")
		}

		res.Request.Header.Del("User-Agent")
		res.Request.Header.Del("Range")
		out.Layers = append(out.Layers, &claircore.Layer{
			Hash:    ccd,
			URI:     res.Request.URL.String(),
			Headers: res.Request.Header,
		})
	}

	return &out, nil
}
