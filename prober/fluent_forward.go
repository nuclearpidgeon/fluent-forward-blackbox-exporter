// Copyright 2024 Stewart Webb (swebb.id.au)
// Adapted from prober/tcp.go in blackbox_exporter, Copyright 2016 The
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

package prober

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/prometheus/blackbox_exporter/config"
	"github.com/vmihailenco/msgpack/v5"
	"github.com/vmihailenco/msgpack/v5/msgpcode"
)

func writeUint32RawBytes(w io.Writer, buf []byte, n uint32) (nn int, e error) {
	// adapted from msgpack Encoder.write4(), but without the initial tag byte
	buf[0] = byte(n >> 24)
	buf[1] = byte(n >> 16)
	buf[2] = byte(n >> 8)
	buf[3] = byte(n)
	return w.Write(buf)
}

func ProbeFluentForward(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) bool {
	probeSSLEarliestCertExpiry := prometheus.NewGauge(sslEarliestCertExpiryGaugeOpts)
	probeSSLLastChainExpiryTimestampSeconds := prometheus.NewGauge(sslChainExpiryInTimeStampGaugeOpts)
	probeSSLLastInformation := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "probe_ssl_last_chain_info",
			Help: "Contains SSL leaf certificate information",
		},
		[]string{"fingerprint_sha256", "subject", "issuer", "subjectalternative"},
	)
	probeTLSVersion := prometheus.NewGaugeVec(
		probeTLSInfoGaugeOpts,
		[]string{"version"},
	)
	// probeFailedDueToRegex := prometheus.NewGauge(prometheus.GaugeOpts{
	// 	Name: "probe_failed_due_to_regex",
	// 	Help: "Indicates if probe failed due to regex",
	// })
	// registry.MustRegister(probeFailedDueToRegex)
	deadline, _ := ctx.Deadline()

	conn, err := dialTCP(ctx, target, module, registry, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Error dialing TCP", "err", err)
		return false
	}
	defer conn.Close()
	level.Info(logger).Log("msg", "Successfully dialed")

	// Set a deadline to prevent the following code from blocking forever.
	// If a deadline cannot be set, better fail the probe by returning an error
	// now rather than blocking forever.
	if err := conn.SetDeadline(deadline); err != nil {
		level.Error(logger).Log("msg", "Error setting deadline", "err", err)
		return false
	}
	if module.TCP.TLS {
		state := conn.(*tls.Conn).ConnectionState()
		registry.MustRegister(probeSSLEarliestCertExpiry, probeTLSVersion, probeSSLLastChainExpiryTimestampSeconds, probeSSLLastInformation)
		probeSSLEarliestCertExpiry.Set(float64(getEarliestCertExpiry(&state).Unix()))
		probeTLSVersion.WithLabelValues(getTLSVersion(&state)).Set(1)
		probeSSLLastChainExpiryTimestampSeconds.Set(float64(getLastChainExpiry(&state).Unix()))
		probeSSLLastInformation.WithLabelValues(getFingerprint(&state), getSubject(&state), getIssuer(&state), getDNSNames(&state)).Set(1)
	}

	msgWriter := msgpack.NewEncoder(conn)

	// Fluentbit's forward plugin sends messages in the following form, which
	// appears to be "Forward Mode" of the Forward protocol:
	// ["exampletag",[[1728021644, {}]],{"chunk":"p8n9gmxTQVC8/nh2wlKKeQ=="}]
	chunkDelimiterBase64 := "p8n9gmxTQVC8/nh2wlKKeQ=="
	timestamp := time.Now()
	// Start the 3-elem array that the message form takes
	msgWriter.EncodeArrayLen(3)
	// message part 1/3: tag
	msgWriter.EncodeString("probetag")

	// messsage part 2/3: one log message
	// use 'forward' mode where logs are delivered in an array
	msgWriter.EncodeArrayLen(1)
	// Log consists of 2 things: timestamp, then record
	msgWriter.EncodeArrayLen(2)
	// Use the 'EventTime' extension format, which is two 32-bit number components
	timestampu32tmpbuf := [4]byte{}
	// 'EventTime' is packaged in an 'ext' bytearray extension type, with ext
	// type 0, then the (eight) bytes of two 32bit ints without any usual
	// msgpack int type prefix.
	msgWriter.EncodeExtHeader(0, 8)
	// The golang msgpack library's EncodeUint32() func writes a msgpcode.Uint32
	// prefix byte, but for the ext8-based timestamp format, we need to write
	// just the bytes of the int32s manually
	// msgWriter.EncodeUint32(uint32(timestamp.Unix()))
	// msgWriter.EncodeUint32(uint32(timestamp.Nanosecond()))
	writeUint32RawBytes(msgWriter.Writer(), timestampu32tmpbuf[:], uint32(timestamp.Unix()))
	writeUint32RawBytes(msgWriter.Writer(), timestampu32tmpbuf[:], uint32(timestamp.Nanosecond()))

	// Send an empty map message :-)
	msgWriter.EncodeMapLen(0)
	// msgWriter.EncodeMapLen(1)
	// msgWriter.EncodeString("message")
	// msgWriter.EncodeString("ping")

	// message part 3/3: options hash
	msgWriter.EncodeMapLen(1)
	// https://github.com/fluent/fluentd/wiki/Forward-Protocol-Specification-v1.5#option
	// "Clients MAY send the `chunk`` option to confirm the server receives
	// event records. The value is a string of Base64 representation of 128
	// bits unique_id which is an ID of a set of events."
	msgWriter.EncodeString("chunk")
	msgWriter.EncodeString(chunkDelimiterBase64)

	// Message sent - now wait for the ack
	foundAck := false
	foundMatchingAck := false

	reader := bufio.NewReader(conn)
	// xxx: set deadline on this?
	c, err := reader.ReadByte()
	if err != nil {
		level.Error(logger).Log("msg", "Error reading first byte of Forward response", "err", err)
		return false
	}
	reader.UnreadByte()
	// Expected response is the fluent 'ack', which should be a map with one "ack"
	// key and the chunk delimiter that was sent in
	if !msgpcode.IsFixedMap(c) {
		level.Error(logger).Log("msg", fmt.Sprintf("Invalid non-map first byte 0x%x in Forward response from server", c), "err", err)
		return false
	}
	level.Debug(logger).Log("msg", "got fixedMap Forward response from server")
	mpDecoder := msgpack.NewDecoder(reader)
	// var resp map[string]interface{}
	// resp, err = mpDecoder.DecodeMap()
	// for k, v := range resp {
	// 	fmt.Println("key: ", k, ", value: ", v)
	// }

	respMapLen, err := mpDecoder.DecodeMapLen()
	if err != nil {
		level.Error(logger).Log("msg", "Error reading length of map in Forward response", "err", err)
		return false
	}

	if respMapLen == -1 {
		level.Error(logger).Log("msg", "Forward response consisted of nil map", "err", err)
		return false
	}

	resp_map_i := 0
	for ; resp_map_i < respMapLen; resp_map_i++ {
		mapKey, err := mpDecoder.DecodeString()
		if err != nil {
			level.Error(logger).Log("msg", fmt.Sprintf("Error decoding Forward response map - failed to decode key at map index %d", resp_map_i), "err", err)
			return false
		}
		mapVal, err := mpDecoder.DecodeInterface()
		if err != nil {
			level.Error(logger).Log("msg", fmt.Sprintf("Error decoding Forward response map - failed to decode value at map index %d", resp_map_i), "err", err)
			return false
		}
		if mapKey == "ack" {
			foundAck = true
			if mapVal == chunkDelimiterBase64 {
				foundMatchingAck = true
				break
			}
		} else {
			level.Error(logger).Log("msg", "Skipped non-matching response key %s")
			continue
		}
	}

	if foundAck {
		if foundMatchingAck {
			return true
		} else {
			level.Error(logger).Log("msg", "Matching ack was not found in Forward response (searched %d map entries)", "err", err)
			return false
		}
	} else {
		level.Error(logger).Log("msg", "No ack was found in Forward response (searched %d map entries)", "err", err)
		return false
	}
}
