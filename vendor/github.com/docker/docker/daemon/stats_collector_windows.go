package daemon

import (
	"time"

	"github.com/docker/docker/container"
)

// newStatsCollector returns a new statsCollector for collection stats
// for a registered container at the specified interval. The collector allows
// non-running containers to be added and will start processing stats when
// they are started.
func (daemon *Daemon) newStatsCollector(interval time.Duration) *statsCollector {
	return &statsCollector{}
}

// statsCollector manages and provides container resource stats
type statsCollector struct {
}

// collect registers the container with the collector and adds it to
// the event loop for collection on the specified interval returning
// a channel for the subscriber to receive on.
func (s *statsCollector) collect(c *container.Container) chan interface{} {
	return nil
}

// stopCollection closes the channels for all subscribers and removes
// the container from metrics collection.
func (s *statsCollector) stopCollection(c *container.Container) {
}

// unsubscribe removes a specific subscriber from receiving updates for a container's stats.
func (s *statsCollector) unsubscribe(c *container.Container, ch chan interface{}) {
}
