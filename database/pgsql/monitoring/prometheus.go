// Copyright 2019 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package monitoring

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	PromErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "clair_pgsql_errors_total",
		Help: "Number of errors that PostgreSQL requests generated.",
	}, []string{"request"})

	PromCacheHitsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "clair_pgsql_cache_hits_total",
		Help: "Number of cache hits that the PostgreSQL backend did.",
	}, []string{"object"})

	PromCacheQueriesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "clair_pgsql_cache_queries_total",
		Help: "Number of cache queries that the PostgreSQL backend did.",
	}, []string{"object"})

	PromQueryDurationMilliseconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "clair_pgsql_query_duration_milliseconds",
		Help: "Time it takes to execute the database query.",
	}, []string{"query", "subquery"})

	PromConcurrentLockVAFV = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "clair_pgsql_concurrent_lock_vafv_total",
		Help: "Number of transactions trying to hold the exclusive Vulnerability_Affects_Feature lock.",
	})
)

func init() {
	prometheus.MustRegister(PromErrorsTotal)
	prometheus.MustRegister(PromCacheHitsTotal)
	prometheus.MustRegister(PromCacheQueriesTotal)
	prometheus.MustRegister(PromQueryDurationMilliseconds)
	prometheus.MustRegister(PromConcurrentLockVAFV)
}

// monitoring.ObserveQueryTime computes the time elapsed since `start` to represent the
// query time.
// 1. `query` is a pgSession function name.
// 2. `subquery` is a specific query or a batched query.
// 3. `start` is the time right before query is executed.
func ObserveQueryTime(query, subquery string, start time.Time) {
	PromQueryDurationMilliseconds.
		WithLabelValues(query, subquery).
		Observe(float64(time.Since(start).Nanoseconds()) / float64(time.Millisecond))
}
