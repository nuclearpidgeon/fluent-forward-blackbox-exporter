// Copyright 2016 The Prometheus Authors
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

package prober

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	helpSSLEarliestCertExpiry     = "Returns last SSL chain expiry in unixtime"
	helpSSLChainExpiryInTimeStamp = "Returns last SSL chain expiry in timestamp"
	helpProbeTLSInfo              = "Returns the TLS version used or NaN when unknown"
	helpProbeTLSCipher            = "Returns the TLS cipher negotiated during handshake"
)

var (
	sslEarliestCertExpiryGaugeOpts = prometheus.GaugeOpts{
		Name: "probe_ssl_earliest_cert_expiry",
		Help: helpSSLEarliestCertExpiry,
	}

	sslChainExpiryInTimeStampGaugeOpts = prometheus.GaugeOpts{
		Name: "probe_ssl_last_chain_expiry_timestamp_seconds",
		Help: helpSSLChainExpiryInTimeStamp,
	}

	probeTLSInfoGaugeOpts = prometheus.GaugeOpts{
		Name: "probe_tls_version_info",
		Help: helpProbeTLSInfo,
	}

	probeTLSCipherGaugeOpts = prometheus.GaugeOpts{
		Name: "probe_tls_cipher_info",
		Help: helpProbeTLSCipher,
	}
)

func getEarliestCertExpiry(state *tls.ConnectionState) time.Time {
	earliest := time.Time{}
	for _, cert := range state.PeerCertificates {
		if (earliest.IsZero() || cert.NotAfter.Before(earliest)) && !cert.NotAfter.IsZero() {
			earliest = cert.NotAfter
		}
	}
	return earliest
}

func getFingerprint(state *tls.ConnectionState) string {
	cert := state.PeerCertificates[0]
	fingerprint := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(fingerprint[:])
}

func getSubject(state *tls.ConnectionState) string {
	cert := state.PeerCertificates[0]
	return cert.Subject.String()
}

func getIssuer(state *tls.ConnectionState) string {
	cert := state.PeerCertificates[0]
	return cert.Issuer.String()
}

func getDNSNames(state *tls.ConnectionState) string {
	cert := state.PeerCertificates[0]
	return strings.Join(cert.DNSNames, ",")
}

func getLastChainExpiry(state *tls.ConnectionState) time.Time {
	lastChainExpiry := time.Time{}
	for _, chain := range state.VerifiedChains {
		earliestCertExpiry := time.Time{}
		for _, cert := range chain {
			if (earliestCertExpiry.IsZero() || cert.NotAfter.Before(earliestCertExpiry)) && !cert.NotAfter.IsZero() {
				earliestCertExpiry = cert.NotAfter
			}
		}
		if lastChainExpiry.IsZero() || lastChainExpiry.Before(earliestCertExpiry) {
			lastChainExpiry = earliestCertExpiry
		}

	}
	return lastChainExpiry
}

func getTLSVersion(state *tls.ConnectionState) string {
	switch state.Version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}

func getTLSCipher(state *tls.ConnectionState) string {
	return tls.CipherSuiteName(state.CipherSuite)
}
