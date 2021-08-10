package graphql

import (
	"context"
	"net/http"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/extension"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/clair/v4/graphql/graph"
	"github.com/quay/clair/v4/graphql/graph/generated"
	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/matcher"
)

var _ http.Handler = (*Handler)(nil)

type Handler struct {
	*handler.Server
}

func New(ctx context.Context, i indexer.Reporter, m matcher.Scanner) (*Handler, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "graphql/New"),
	)

	es := generated.NewExecutableSchema(generated.Config{
		Resolvers: &graph.Resolver{
			Indexer: i,
			Matcher: m,
		},
	})
	srv := handler.New(es)
	srv.AddTransport(transport.Options{})
	srv.AddTransport(transport.GET{})
	srv.AddTransport(transport.POST{})
	srv.Use(extension.Introspection{})

	// TODO(hank) Add caching? The ability to filter the response means that a
	// higher-level cache is less useful. Perhaps add a groupcache-type cache
	// that can be stitched together from SRV records.
	//
	// Similarly, persisted queries seem less useful because of requests being
	// random.

	zlog.Info(ctx).Msg("configured graphql handler")
	return &Handler{Server: srv}, nil
}
