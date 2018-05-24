package integration_test

import (
	"context"
	"flag"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/golang/glog"
	"github.com/grpc-ecosystem/grpc-gateway/examples/gateway"
	server "github.com/grpc-ecosystem/grpc-gateway/examples/server"
	gwruntime "github.com/grpc-ecosystem/grpc-gateway/runtime"
)

var (
	endpoint   = flag.String("endpoint", "localhost:9090", "endpoint of the gRPC service")
	network    = flag.String("network", "tcp", `one of "tcp" or "unix". Must be consistent to -endpoint`)
	swaggerDir = flag.String("swagger_dir", "examples/proto/examplepb", "path to the directory which contains swagger definitions")
)

func runGateway(ctx context.Context, addr string, opts ...gwruntime.ServeMuxOption) error {
	return gateway.Run(ctx, gateway.Options{
		Addr: addr,
		GRPCServer: gateway.Endpoint{
			Network: *network,
			Addr:    *endpoint,
		},
		SwaggerDir: *swaggerDir,
		Mux:        opts,
	})
}

func runServers(ctx context.Context) <-chan error {
	ch := make(chan error, 2)
	go func() {
		if err := server.Run(ctx, *network, *endpoint); err != nil {
			ch <- fmt.Errorf("cannot run grpc service: %v", err)
		}
	}()
	go func() {
		if err := runGateway(ctx, ":8080"); err != nil {
			ch <- fmt.Errorf("cannot run gateway service: %v", err)
		}
	}()
	return ch
}

func TestMain(m *testing.M) {
	flag.Parse()
	defer glog.Flush()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := runServers(ctx)

	ch := make(chan int, 1)
	go func() {
		time.Sleep(100 * time.Millisecond)
		ch <- m.Run()
	}()

	select {
	case err := <-errCh:
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	case status := <-ch:
		cancel()
		os.Exit(status)
	}
}
