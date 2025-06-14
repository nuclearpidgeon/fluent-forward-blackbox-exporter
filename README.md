# Fluent Forward Blackbox exporter

This is a cut-down version of the [Prometheus blackbox exporter](https://github.com/prometheus/blackbox_exporter) that targets the more niche protocol scenario of probing a Fluent Forward endpoint, as implemented by the [Fluentbit](https://fluentbit.io/) and [Fluentd](https://www.fluentd.org/) projects for receiving/sending/transporting log data (and other application/system telemetry such as metrics and traces).

The Fluent Forward protocol uses [msgpack](https://github.com/msgpack/msgpack) structures over TCP. is documented here:
* https://github.com/fluent/fluentd/wiki/Forward-Protocol-Specification-v1
* https://github.com/fluent/fluentd/wiki/Forward-Protocol-Specification-v1.5

See here for docs on the input plugins that handle Forward input data:

* Forward input for fluentbit: https://docs.fluentbit.io/manual/pipeline/inputs/forward
* Forward input for fluentd: https://docs.fluentd.org/input/forward

## Usage

1) Build the project with `go build`
2) Create a config file that specifies a `forward` prober - e.g.
```yaml
modules:
  fluent_forward_test:
    prober: forward
    timeout: 5s
```
3) Start the exporter with the config file:
    * `./fluent-forward-blackbox-exporter --config.file my-forward-probe-cfg.yml`
4) Test the probe with a scrape (use debug mode for additional logs). You should see `probe_success 1` at the end of the output.
    * `curl -v "localhost:9115/probe?target=127.0.0.1%3A24224&module=fluent_forward_test&debug=true"`
    * Fluentbit oneliner for setting up a localhost forward input to test the probe against:<br>`fluent-bit -i forward -o stdout -m '*'`

## Purpose/scope

Much of the structure of this project is essentially a cut-down copy/fork of the original blackbox_exporter project. I took this approach because the Fluent Forward protocol seemed quite a niche one compared to the more standardised protocols that the original project has probes available for (HTTP, TCP, gRPC), and I didn't expect that the Prometheus authors would necessarily want to bring a probe like this into the scope of code they would have to maintain for the blackbox_exporter project. Maintaining some kind of patch-based fork of the project seemed like too much effort for myself long-term, so I ended up settling on a skeleton-based fork that removed all the other probes to keep the scope of this codebase much more constrained.
It would be entirely possible to include the Fluent Forward prober into the blackbox_exporter project (and in fact this was how I first wrote the code). I'm happy to help facilitate this if anyone wants it, and if the Prometheus authors are interested in including the probe in their codebase.
A more useful integration approach might be some kind of more generic byte protocol / msgpack request/response probe module, but the scope of this would be much wider than just Fluent Forward so I would leave this to another project / development effort with appropriate motivating examples.

## License

The original blackbox_exporter project is Apache 2.0 licensed. I have continued the adoption of this license for this project, however I have marked the Fluent Forward probing code in particular with my own copyright as it is my original work.
As mentioned above, much of the structure and code of this project is essentially a cut-down copy/fork of the original blackbox_exporter project. I have kept copyright notice on the sections/files written by The Prometheus Authors.
If you find any issues with the copyright/notices/licensing, feel free to raise a Github issue in regards to them.

## Extra References

* IBM of all entities have written a Go client for fluent forward that is another reference for working with the Forward protocol:
    * https://github.com/IBM/fluent-forward-go
    * https://github.com/IBM/fluent-forward-go/blob/main/fluent/protocol/message.go
* The Fluent org also have a "Fluentd Forwarder" project written in Go, from ~2015
    * https://github.com/fluent/fluentd-forwarder/
    * https://github.com/fluent/fluentd-forwarder/blob/master/input.go
* The prober module code makes use of Go's `Context` interface for managing lifetimes of connection attempts
    * https://go.dev/blog/context
* Go module reference
    * https://go.dev/ref/mod