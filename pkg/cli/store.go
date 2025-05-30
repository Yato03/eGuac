//
// Copyright 2023 The GUAC Authors.
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

package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/pflag"
)

var flagStore = make(map[string]*pflag.Flag)

const (
	ConfigLogLevelVar = "log-level"
)

var NotFound = errors.New("Flag not found")

func init() {
	set := &pflag.FlagSet{}

	// Set of all flags used across GUAC clis and subcommands. Use consistent
	// names for config file.
	set.String("csub-addr", "localhost:2782", "address to connect to collect-sub service")
	set.Bool("csub-tls", false, "enable tls connection to the server")
	set.Bool("csub-tls-skip-verify", false, "skip verifying server certificate (for self-signed certificates for example)")
	set.Bool("use-csub", true, "use collectsub server for datasource")

	set.Int("csub-listen-port", 2782, "port to listen to on collect-sub service")
	set.String("csub-tls-cert-file", "", "path to the TLS certificate in PEM format for collect-sub service")
	set.String("csub-tls-key-file", "", "path to the TLS key in PEM format for collect-sub service")

	set.String("gql-backend", "keyvalue", "backend used for graphql api server: [keyvalue | arango (experimental) | ent (experimental) | neo4j (unmaintained)]")
	set.Int("gql-listen-port", 8080, "port used for graphql api server")
	set.String("gql-tls-cert-file", "", "path to the TLS certificate in PEM format for graphql api server")
	set.String("gql-tls-key-file", "", "path to the TLS key in PEM format for graphql api server")
	set.Bool("gql-debug", false, "debug flag which enables the graphQL playground")
	set.Bool("gql-trace", false, "flag which enables tracing of graphQL requests and responses on the console")

	// blob store address
	set.String("blob-addr", "file:///tmp/blobstore?no_tmp_dir=true", "gocloud connection string for blob store configured via https://gocloud.dev/howto/blob/ (default: filesystem)")

	// pubsub address
	set.String("pubsub-addr", "nats://127.0.0.1:4222", "gocloud connection string for pubsub configured via https://gocloud.dev/howto/pubsub/ (default is nats://127.0.0.1:4222)")

	// enable/disable publish to queue
	set.Bool("publish-to-queue", true, "enable/disable message publish to queue")

	// the ingestor will query and ingest OSV for vulnerabilities
	set.Bool("add-vuln-on-ingest", false, "if enabled, the ingestor will query and ingest OSV for vulnerabilities. Warning: This will increase ingestion times")
	set.Bool("add-vuln-metadata", false, "if enabled, the osv certifier will add metadata to vulnerabilities from OSV")

	// the ingestor will query and ingest clearly defined for licenses
	set.Bool("add-license-on-ingest", false, "if enabled, the ingestor will query and ingest clearly defined for licenses. Warning: This will increase ingestion times")

	// the ingestor will query and ingest endoflife.date for EOL
	set.Bool("add-eol-on-ingest", false, "if enabled, the ingestor will query and ingest endoflife.date for EOL data. Warning: This will increase ingestion times")

	set.String("gql-addr", "http://localhost:8080/query", "endpoint used to connect to graphQL server")

	set.String("rest-api-server-port", "8081", "port to serve the REST API from")
	set.String("rest-api-tls-cert-file", "", "path to the TLS certificate in PEM format for rest api server")
	set.String("rest-api-tls-key-file", "", "path to the TLS key in PEM format for rest api server")
	set.Bool("db-direct-connection", false, "[experimental] connect directly to the database that backs the gql API for optimized endpoint implementations")

	set.String("verifier-key-path", "", "path to pem file to verify dsse")
	set.String("verifier-key-id", "", "ID of the key to be stored")

	// certifier
	set.Bool("service-poll", true, "sets the collector or certifier to polling mode")
	set.BoolP("poll", "p", false, "sets the collector or certifier to polling mode")

	// set the batch size for the package pagination query
	set.Int("certifier-batch-size", 60000, "sets the batch size for pagination query for the certifier")
	// add artificial latency to throttle the certifier
	set.String("certifier-latency", "", "sets artificial latency on the certifier. Defaults to empty string (not enabled) but can set m, h, s...etc")

	// deps.dev
	// add artificial latency to throttle deps.dev
	set.String("deps-dev-latency", "", "sets artificial latency on the deps.dev collector. Defaults to empty string (not enabled) but can set m, h, s...etc")

	set.Bool("retrieve-dependencies", true, "enable the deps.dev collector to retrieve package dependencies")

	set.Bool("enable-prometheus", false, "enable prometheus metrics")
	set.Int("prometheus-port", 9091, "port to listen to on prometheus server")
	set.Bool("enable-otel", false, "enable otel metrics and tracing")

	set.StringP("interval", "i", "5m", "if polling set interval, m, h, s, etc.")

	set.IntP("last-scan", "l", 4, "hours since the last scan was run. If not set, run on all packages/sources")

	set.BoolP("cert-good", "g", false, "enable to certifyGood, otherwise defaults to certifyBad")
	set.BoolP("package-name", "n", false, "if type is package, enable if attestation is at package-name level (for all versions), defaults to specific version")

	set.StringP("justification", "j", "", "justification for the metadata")

	set.IntP("search-depth", "d", 0, "depth to search, 0 has no limit")

	set.StringP("vuln-id", "v", "", "vulnerability ID to check")
	set.Int("num-path", 0, "number of paths to return, 0 means all paths")
	set.String("start-purl", "", "string input of purl with package to start search from")
	set.String("stop-purl", "", "string input of purl with package to stop search at")
	set.Bool("is-pkg-version-start", false, "for query path are you inputting a packageVersion to start the search from (if false then packageName)")
	set.Bool("is-pkg-version-stop", false, "for query path are you inputting a packageVersion to stop the search at (if false then packageName)")

	// Google Cloud platform flags
	set.String("gcp-credentials-path", "", "Path to the Google Cloud service account credentials json file.\nAlternatively you can set GOOGLE_APPLICATION_CREDENTIALS=<path> in your environment.")

	// S3 flags
	set.String("s3-url", "", "url of the s3 endpoint")
	set.String("s3-path", "", "path to folder containing documents in the s3 bucket")
	set.String("s3-bucket", "", "bucket in the s3 provider")
	set.String("s3-item", "", "item in the s3 provider")
	set.String("s3-mp", "kafka", "message provider (sqs or kafka)")
	set.String("s3-mp-endpoint", "", "endpoint for the message provider")
	set.String("s3-queues", "", "comma-separated list of queue/topic names")
	set.String("s3-region", "us-east-1", "aws region")

	// GitHub collector options
	set.String("github-mode", "release", "mode to run github collector in: [release | workflow]")
	set.String("github-sbom", "", "name of sbom file to look for in github release.")
	set.String("github-workflow-file", "", "name of workflow file to look for in github workflow. \nThis will be the name of the actual file, not the workflow name (i.e. ci.yaml).")

	set.String("header-file", "", "a text file containing HTTP headers to send to the GQL server, in RFC 822 format")

	set.VisitAll(func(f *pflag.Flag) {
		flagStore[f.Name] = f
	})
}

func BuildFlags(names []string) (*pflag.FlagSet, error) {
	rv := &pflag.FlagSet{}
	for _, n := range names {
		f, ok := flagStore[n]
		if !ok {
			return nil, fmt.Errorf("%w : %s", NotFound, n)
		}
		rv.AddFlag(f)
	}
	return rv, nil
}
