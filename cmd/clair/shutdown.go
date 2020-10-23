package main

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"golang.org/x/sync/errgroup"
)

// Shutdown aggregates http.Sever Shutdown methods.
type Shutdown struct {
	mu sync.Mutex
	m  map[*http.Server]struct{}
}

// Add registers a server.
func (s *Shutdown) Add(srv *http.Server) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = make(map[*http.Server]struct{})
	}
	s.m[srv] = struct{}{}
}

// Shutdown calls Shutdown on all added Servers. If a timeout is needed, it
// should be done via the passed Context.
func (s *Shutdown) Shutdown(ctx context.Context) error {
	s.mu.Lock() // Leave locked forever
	eg := &errgroup.Group{}
	for srv := range s.m {
		srv := srv
		eg.Go(func() error {
			if err := srv.Shutdown(ctx); err != nil {
				return fmt.Errorf("unable to shutdown %q: %w", srv.Addr, err)
			}
			return nil
		})
		delete(s.m, srv)
	}
	return eg.Wait()
}
