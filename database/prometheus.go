package database

import (
	"time"

	"github.com/coreos/clair/utils"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	PromErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "clair_sql_errors_total",
		Help: "Number of errors that SQL requests generated.",
	}, []string{"request"})

	PromCacheHitsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "clair_sql_cache_hits_total",
		Help: "Number of cache hits that the SQL backend did.",
	}, []string{"object"})

	PromCacheQueriesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "clair_sql_cache_queries_total",
		Help: "Number of cache queries that the SQL backend did.",
	}, []string{"object"})

	PromQueryDurationMilliseconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "clair_sql_query_duration_milliseconds",
		Help: "Time it takes to execute the database query.",
	}, []string{"query", "subquery"})

	PromConcurrentLockVAFV = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "clair_sql_concurrent_lock_vafv_total",
		Help: "Number of transactions trying to hold the exclusive Vulnerability_Affects_FeatureVersion lock.",
	})
)

func init() {
	prometheus.MustRegister(PromErrorsTotal)
	prometheus.MustRegister(PromCacheHitsTotal)
	prometheus.MustRegister(PromCacheQueriesTotal)
	prometheus.MustRegister(PromQueryDurationMilliseconds)
	prometheus.MustRegister(PromConcurrentLockVAFV)
}

func ObserveQueryTime(query, subquery string, start time.Time) {
	utils.PrometheusObserveTimeMilliseconds(PromQueryDurationMilliseconds.WithLabelValues(query, subquery), start)
}
