// Copyright 2024 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package metrics

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
)

var (
	// max size of data items to buffer before dropping
	// new incoming data items
	dataItemCount = 100000
)

// Tag is added metadata for metrics
type Tag struct {
	// Key is tag name
	Key string
	// Value is tag data
	Value string
}

// Manager is a manager of metrics plugins
type Manager struct {
	wg  sync.WaitGroup
	ctx context.Context

	config Config

	publishers  []publisher
	addDataChan chan datapoint
}

type Config struct {
	ServiceName      string
	StatsdServers    string
	DogStatsdServers string
}

// NewManager initializes metrics plugins and returns a new metrics manager
func NewManager(ctx context.Context, conf Config) (*Manager, error) {
	if len(conf.StatsdServers) == 0 && len(conf.DogStatsdServers) == 0 {
		return nil, nil
	}

	if conf.ServiceName == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("failed to get hostname: %w", err)
		}
		conf.ServiceName = hostname
	}

	addDataChan := make(chan datapoint, dataItemCount)

	mgr := &Manager{
		addDataChan: addDataChan,
		ctx:         ctx,
		config:      conf,
	}

	// setup statsd endpoints
	if len(conf.StatsdServers) > 0 {
		statsdServers := strings.Split(conf.StatsdServers, ",")

		for _, server := range statsdServers {
			statsd, err := newStatsd(server, conf.ServiceName)
			if err != nil {
				return nil, err
			}
			mgr.publishers = append(mgr.publishers, statsd)
		}
	}

	// setup dogstatsd endpoints
	if len(conf.DogStatsdServers) > 0 {
		dogStatsdServers := strings.Split(conf.DogStatsdServers, ",")

		for _, server := range dogStatsdServers {
			dogStatsd, err := newDogStatsd(server, conf.ServiceName)
			if err != nil {
				return nil, err
			}
			mgr.publishers = append(mgr.publishers, dogStatsd)
		}
	}

	mgr.wg.Add(1)
	go mgr.addForwarder(addDataChan)

	return mgr, nil
}

func (m *Manager) Send(err error, action string, count int64) {
	// In case of Authentication failures, url parsing ...
	if action == "" {
		action = ActionUndetected
	}
	if err != nil {
		m.increment(action, "failed_count")
	} else {
		m.increment(action, "success_count")
	}

	switch action {
	case ActionPutObject:
		m.add(action, "bytes_written", count)
		m.increment(action, "object_created_count")
	case ActionCompleteMultipartUpload:
		m.increment(action, "object_created_count")
	case ActionUploadPart:
		m.add(action, "bytes_written", count)
	case ActionGetObject:
		m.add(action, "bytes_read", count)
	case ActionDeleteObject:
		m.increment(action, "object_removed_count")
	case ActionDeleteObjects:
		m.add(action, "object_removed_count", count)
	}
}

// increment increments the key by one
func (m *Manager) increment(module, key string, tags ...Tag) {
	m.add(module, key, 1, tags...)
}

// add adds value to key
func (m *Manager) add(module, key string, value int64, tags ...Tag) {
	if m.ctx.Err() != nil {
		return
	}

	d := datapoint{
		module: module,
		key:    key,
		value:  value,
		tags:   tags,
	}

	select {
	case m.addDataChan <- d:
	default:
		// channel full, drop the updates
	}
}

// Close closes metrics channels, waits for data to complete, closes all plugins
func (m *Manager) Close() {
	// drain the datapoint channels
	close(m.addDataChan)
	m.wg.Wait()

	// close all publishers
	for _, p := range m.publishers {
		p.Close()
	}
}

// publisher is the interface for interacting with the metrics plugins
type publisher interface {
	Add(module, key string, value int64, tags ...Tag)
	Close()
}

func (m *Manager) addForwarder(addChan <-chan datapoint) {
	for data := range addChan {
		for _, s := range m.publishers {
			s.Add(data.module, data.key, data.value, data.tags...)
		}
	}
	m.wg.Done()
}

type datapoint struct {
	module string
	key    string
	value  int64
	tags   []Tag
}