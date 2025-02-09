// Copyright 2025 Stewart Webb (swebb.id.au)
// Adapted from config/config.go in blackbox_exporter, Copyright 2016 The
// Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"sync"
	"time"

	yaml "gopkg.in/yaml.v3"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	promconfig "github.com/prometheus/common/config"
)

var (
	// Config types have static defaults that are copied then overwritten by
	// any parsed real config

	DefaultModule = Module{
		FluentForward: DefaultFluentForwardProbe,
	}

	DefaultFluentForwardProbe = FluentForwardProbe{
		Tag:                "blackboxprobemsg",
		IPProtocolFallback: true,
	}
)

type Config struct {
	Modules map[string]Module `yaml:"modules"`
}

type SafeConfig struct {
	sync.RWMutex
	C                   *Config
	configReloadSuccess prometheus.Gauge
	configReloadSeconds prometheus.Gauge
}

func NewSafeConfig(reg prometheus.Registerer) *SafeConfig {
	configReloadSuccess := promauto.With(reg).NewGauge(prometheus.GaugeOpts{
		Namespace: "fluent_forward_blackbox_exporter",
		Name:      "config_last_reload_successful",
		Help:      "Blackbox exporter config loaded successfully.",
	})

	configReloadSeconds := promauto.With(reg).NewGauge(prometheus.GaugeOpts{
		Namespace: "fluent_forward_blackbox_exporter",
		Name:      "config_last_reload_success_timestamp_seconds",
		Help:      "Timestamp of the last successful configuration reload.",
	})
	return &SafeConfig{C: &Config{}, configReloadSuccess: configReloadSuccess, configReloadSeconds: configReloadSeconds}
}

func (sc *SafeConfig) ReloadConfig(confFile string, logger log.Logger) (err error) {
	var c = &Config{}
	defer func() {
		if err != nil {
			sc.configReloadSuccess.Set(0)
		} else {
			sc.configReloadSuccess.Set(1)
			sc.configReloadSeconds.SetToCurrentTime()
		}
	}()

	yamlReader, err := os.Open(confFile)
	if err != nil {
		return fmt.Errorf("error reading config file: %s", err)
	}
	defer yamlReader.Close()
	decoder := yaml.NewDecoder(yamlReader)
	decoder.KnownFields(true)

	if err = decoder.Decode(c); err != nil {
		return fmt.Errorf("error parsing config file: %s", err)
	}

	// for name, module := range c.Modules {

	// }

	sc.Lock()
	sc.C = c
	sc.Unlock()

	return nil
}

// Regexp encapsulates a regexp.Regexp and makes it YAML marshalable.
type Regexp struct {
	*regexp.Regexp
	original string
}

// NewRegexp creates a new anchored Regexp and returns an error if the
// passed-in regular expression does not compile.
func NewRegexp(s string) (Regexp, error) {
	regex, err := regexp.Compile(s)
	return Regexp{
		Regexp:   regex,
		original: s,
	}, err
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (re *Regexp) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	r, err := NewRegexp(s)
	if err != nil {
		return fmt.Errorf("\"Could not compile regular expression\" regexp=\"%s\"", s)
	}
	*re = r
	return nil
}

// MarshalYAML implements the yaml.Marshaler interface.
func (re Regexp) MarshalYAML() (interface{}, error) {
	if re.original != "" {
		return re.original, nil
	}
	return nil, nil
}

// MustNewRegexp works like NewRegexp, but panics if the regular expression does not compile.
func MustNewRegexp(s string) Regexp {
	re, err := NewRegexp(s)
	if err != nil {
		panic(err)
	}
	return re
}

type Module struct {
	Prober        string             `yaml:"prober,omitempty"`
	Timeout       time.Duration      `yaml:"timeout,omitempty"`
	FluentForward FluentForwardProbe `yaml:"fluentforward,omitempty"`
}

type FluentForwardProbe struct {
	IPProtocol         string               `yaml:"preferred_ip_protocol,omitempty"`
	IPProtocolFallback bool                 `yaml:"ip_protocol_fallback,omitempty"`
	SourceIPAddress    string               `yaml:"source_ip_address,omitempty"`
	Tag                string               `yaml:"tag,omitempty"`
	TLS                bool                 `yaml:"tls,omitempty"`
	TLSConfig          promconfig.TLSConfig `yaml:"tls_config,omitempty"`
}

// UnmarshalYAML funcs implement the yaml.Unmarshaler interface.

func (s *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Config
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	return nil
}

func (s *Module) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*s = DefaultModule
	type plain Module
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	return nil
}

func (s *FluentForwardProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*s = DefaultFluentForwardProbe
	type plain FluentForwardProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}

	if s.Tag == "" {
		return errors.New("non-empty Fluent tag must be set for Fluent Forward module")
	}

	return nil
}
