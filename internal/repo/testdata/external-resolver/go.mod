// A module outside devproof, used to prove the public resolver contract can
// be implemented from outside it. Under testdata, so the parent module
// ignores it entirely.
module example.com/external-resolver

go 1.27.1

require github.com/thingzio/devproof v0.0.0

require (
	dario.cat/mergo v1.0.2 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/ProtonMail/go-crypto v1.4.1 // indirect
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.6.5 // indirect
	github.com/coreos/go-oidc/v3 v3.21.0 // indirect
	github.com/cyberphone/json-canonicalization v0.0.0-20241213102144-19d51d7fe467 // indirect
	github.com/cyphar/filepath-securejoin v0.7.0 // indirect
	github.com/digitorus/pkcs7 v0.0.0-20260821105541-05f79448fa77 // indirect
	github.com/digitorus/timestamp v0.0.0-20250524132541-c45532741eea // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.9.1 // indirect
	github.com/go-git/go-git/v5 v5.19.2 // indirect
	github.com/go-jose/go-jose/v4 v4.1.5 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-openapi/analysis v1.0.0 // indirect
	github.com/go-openapi/errors v0.22.8 // indirect
	github.com/go-openapi/jsonpointer v1.0.1 // indirect
	github.com/go-openapi/jsonreference v1.0.2 // indirect
	github.com/go-openapi/loads v0.25.3 // indirect
	github.com/go-openapi/runtime v0.33.2 // indirect
	github.com/go-openapi/runtime/server-middleware v0.33.2 // indirect
	github.com/go-openapi/spec v1.0.1 // indirect
	github.com/go-openapi/strfmt v0.27.2 // indirect
	github.com/go-openapi/swag/conv v0.29.2 // indirect
	github.com/go-openapi/swag/fileutils v0.29.2 // indirect
	github.com/go-openapi/swag/jsonutils v0.29.2 // indirect
	github.com/go-openapi/swag/loading v0.29.2 // indirect
	github.com/go-openapi/swag/mangling v0.29.2 // indirect
	github.com/go-openapi/swag/pools v0.29.2 // indirect
	github.com/go-openapi/swag/stringutils v0.29.2 // indirect
	github.com/go-openapi/swag/typeutils v0.29.2 // indirect
	github.com/go-openapi/swag/yamlutils v0.29.2 // indirect
	github.com/go-openapi/validate v1.0.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/certificate-transparency-go v1.3.3 // indirect
	github.com/google/go-containerregistry v0.22.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.30.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.8 // indirect
	github.com/in-toto/attestation v1.2.0 // indirect
	github.com/in-toto/in-toto-golang v0.11.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jedisct1/go-minisign v0.0.0-20260527172527-a09352b57a22 // indirect
	github.com/kevinburke/ssh_config v1.6.0 // indirect
	github.com/klauspost/cpuid/v2 v2.4.0 // indirect
	github.com/oklog/ulid/v2 v2.1.2 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/pjbgf/sha1cd v0.6.0 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sassoftware/relic/v8 v8.2.0 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.11.1 // indirect
	github.com/sergi/go-diff v1.4.0 // indirect
	github.com/shibumi/go-pathspec v1.3.0 // indirect
	github.com/sigstore/protobuf-specs v0.5.2 // indirect
	github.com/sigstore/rekor v1.5.4 // indirect
	github.com/sigstore/rekor-tiles/v2 v2.3.0 // indirect
	github.com/sigstore/sigstore v1.10.10 // indirect
	github.com/sigstore/sigstore-go v1.3.0 // indirect
	github.com/sigstore/timestamp-authority/v2 v2.1.3 // indirect
	github.com/skeema/knownhosts v1.3.3 // indirect
	github.com/spf13/cobra v1.10.2 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/theupdateframework/go-tuf v0.7.0 // indirect
	github.com/theupdateframework/go-tuf/v2 v2.4.2 // indirect
	github.com/transparency-dev/formats v0.1.1 // indirect
	github.com/transparency-dev/merkle v0.0.2 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.46.0 // indirect
	go.opentelemetry.io/otel/metric v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/term v0.46.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260911204522-f61a6ca850bd // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260911204522-f61a6ca850bd // indirect
	google.golang.org/grpc v1.83.2 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/klog/v2 v2.140.0 // indirect
	oras.land/oras-go/v2 v2.6.2 // indirect
)

replace github.com/thingzio/devproof => ../../../..
