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
	// warning: missing database configuration (at $.indexer.database)
	// warning: missing database configuration (at $.matcher.database)
	// warning: updater period is very aggressive: most sources are updated daily (at $.matcher.period)
	// warning: update garbage collection is off (at $.matcher.update_retention)
	// warning: missing database configuration (at $.notifier.database)
	// warning: interval is very fast: may result in increased workload (at $.notifier.poll_interval)
	// warning: interval is very fast: may result in increased workload (at $.notifier.delivery_interval)
}
