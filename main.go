package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"github.com/brave/nitriding"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	log "github.com/sirupsen/logrus"
)

const (
	certificateValidity = time.Hour * 24 * 356
	// parentCID determines the CID (analogous to an IP address) of the parent
	// EC2 instance.  According to the AWS docs, it is always 3:
	// https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html
	parentCID = 3
	// The following paths are handled by nitriding.
	pathHelloWorld  = "/hello-world"
	pathAttestation = "/enclave/attestation"

	pathProxy = "/*"
)

var (
	inEnclave         = true
	errNoKeyMaterial  = errors.New("no key material registered")
	errCfgMissingFQDN = errors.New("given config is missing FQDN")
	errCfgMissingPort = errors.New("given config is missing port")
)

func main() {
	c := &nitriding.Config{
		FQDN:          "localhost",
		ExtPort:       uint16(8443),
		IntPort:       uint16(8444),
		HostProxyPort: uint32(1024),
		UseACME:       false,
		AppWebSrv:     nil,
	}

	enclave, err := NewEnclave(c)
	if err != nil {
		log.Fatalf("Failed to create enclave: %v", err)
	}

	if err := enclave.Start(); err != nil {
		log.Fatalf("Enclave terminated: %v", err)
	}

	// Block on this read forever.
	<-make(chan struct{})
}

// proxyHandler returns an HTTP handler that proxies HTTP requests to the
// enclave-internal HTTP server of our enclave application.
func proxyHandler(e *Enclave) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		e.revProxy.ServeHTTP(w, r)
	}
}

// NewEnclave creates and returns a new enclave with the given config.
func NewEnclave(cfg *nitriding.Config) (*Enclave, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("failed to create enclave: %w", err)
	}

	e := &Enclave{
		cfg: cfg,
		pubSrv: http.Server{
			Addr:    fmt.Sprintf(":%d", cfg.ExtPort),
			Handler: chi.NewRouter(),
		},
		hashes: new(AttestationHashes),
		stop:   make(chan bool),
		ready:  make(chan bool),
	}

	if cfg.Debug {
		e.pubSrv.Handler.(*chi.Mux).Use(middleware.Logger)
	}

	// Register public HTTP API.
	m := e.pubSrv.Handler.(*chi.Mux)
	m.Get(pathHelloWorld, helloWorld(e))
	m.Get(pathAttestation, attestationHandler(e.hashes))

	// Configure our reverse proxy if the enclave application exposes an HTTP
	// server.
	if cfg.AppWebSrv != nil {
		e.revProxy = httputil.NewSingleHostReverseProxy(cfg.AppWebSrv)
		e.pubSrv.Handler.(*chi.Mux).Handle(pathProxy, proxyHandler(e))
	}

	return e, nil
}

type Enclave struct {
	sync.RWMutex
	cfg         *nitriding.Config
	pubSrv      http.Server
	revProxy    *httputil.ReverseProxy
	hashes      *AttestationHashes
	keyMaterial any
	ready, stop chan bool
}

func (e *Enclave) Start() error {
	var err error
	errPrefix := "failed to start Nitro Enclave"

	if err = setFdLimit(e.cfg.FdCur, e.cfg.FdMax); err != nil {
		log.Printf("Failed to set new file descriptor limit: %s", err)
	}
	if err = configureLoIface(); err != nil {
		return fmt.Errorf("%s: %w", errPrefix, err)
	}

	// Start enclave-internal HTTP server.
	go runNetworking(e.cfg, e.stop)

	if err != nil {
		return fmt.Errorf("%s: failed to create certificate: %w", errPrefix, err)
	}

	if err = startWebServers(e); err != nil {
		return fmt.Errorf("%s: %w", errPrefix, err)
	}

	return nil
}

// startWebServers starts both our public-facing and our enclave-internal Web
// server in a goroutine.
func startWebServers(e *Enclave) error {
	log.Println("Public Web server.")
	go func() {
		if err := e.pubSrv.ListenAndServe(); err != nil {
			log.Errorf("Public Web server terminated: %v", err)
		}
	}()

	return nil
}

func helloWorld(e *Enclave) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp, err := http.Get("https://jsonplaceholder.typicode.com/posts/1")
		if err != nil {
			log.Fatalln(err)
		}

		// We Read the response body on the line below.
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatalln(err)
		}

		// Convert the body to type string
		sb := string(body)
		log.Println(sb)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello World!"))
	}
}
