package config

import "fmt"

func ExampleLint() {
	var c Config
	c.Auth.PSK = &AuthPSK{}
	ws, err := Lint(&c)
	fmt.Println("error:", err)
	for _, w := range ws {
		fmt.Printf("warning: %v\n", &w)
	}
	// Output:
	// error: <nil>
	// warning: http listen address not provided, default will be used (at $.http_listen_addr)
	// warning: introspection address not provided, default will be used (at $.introspection_addr)
	// warning: connection string is empty and no relevant environment variables found (at $.indexer.connstring)
	// warning: connection string is empty and no relevant environment variables found (at $.matcher.connstring)
	// warning: updater period is very aggressive: most sources are updated daily (at $.matcher.period)
	// warning: update garbage collection is off (at $.matcher.update_retention)
	// warning: connection string is empty and no relevant environment variables found (at $.notifier.connstring)
	// warning: interval is very fast: may result in increased workload (at $.notifier.poll_interval)
	// warning: interval is very fast: may result in increased workload (at $.notifier.delivery_interval)
}
