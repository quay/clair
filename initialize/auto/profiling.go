package auto

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Profiling enables block and mutex profiling.
//
// This function uses the magic environment variable "CLAIRDEBUG" to control the
// values used. This escape hatch will go away in the future.
func Profiling() {
	// Catch contention at a granularity of 1 microsecond.
	blockCur := 1000
	// Catch 1/10 mutex contention events.
	mutexCur := 10
	fromEnv := false
	if s, ok := os.LookupEnv(`CLAIRDEBUG`); ok {
		var err error
		for _, kv := range strings.Split(s, ",") {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			switch k {
			case "blockprofile":
				fromEnv = true
				blockCur, err = strconv.Atoi(v)
			case "mutexprofile":
				fromEnv = true
				mutexCur, err = strconv.Atoi(v)
			default:
			}
			if err != nil {
				panic(err)
			}
		}
	}

	runtime.SetBlockProfileRate(blockCur)
	mutexPrev := runtime.SetMutexProfileFraction(mutexCur)
	msgs = append(msgs, func(ctx context.Context) {
		slog.InfoContext(ctx, "profiling rates configured",
			"from_env", fromEnv,
			"block_rate", time.Duration(blockCur)*time.Nanosecond,
			"prev_mutex_frac", fmt.Sprintf("1/%d", mutexPrev),
			"cur_mutex_frac", fmt.Sprintf("1/%d", mutexCur))
	})
}
