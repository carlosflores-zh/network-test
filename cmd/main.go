package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"github.com/brave/nitriding"
	enclave "github.com/edgebitio/nitro-enclaves-sdk-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/hf/nitrite"
	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"

	"network-test/pkg/attestation"
	"network-test/pkg/system"
)

const (
	certificateValidity = time.Hour * 24 * 356
	// ParentCID  determines the CID (analogous to an IP address) of the parent
	// EC2 instance.  According to the AWS docs, it is always 3:
	// https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html
	ParentCID = 3
	// The following paths are handled by nitriding.
	pathHelloWorld  = "/hello-world"
	pathAttestation = "/enclave/attestation"
	autoAttestation = "/enclave/test-attestation"

	pathProxy = "/*"
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

	enclave, err := NewEnclave(c, ParentCID)
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
func NewEnclave(cfg *nitriding.Config, ParentCID uint32) (*Enclave, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("failed to create enclave: %w", err)
	}

	e := &Enclave{
		cfg: cfg,
		pubSrv: http.Server{
			Addr:    fmt.Sprintf(":%d", cfg.ExtPort),
			Handler: chi.NewRouter(),
		},
		hashes:    new(attestation.Hashes),
		stop:      make(chan bool),
		ready:     make(chan bool),
		ParentCID: ParentCID,
	}

	if cfg.Debug {
		e.pubSrv.Handler.(*chi.Mux).Use(middleware.Logger)
	}

	// Register public HTTP API.
	m := e.pubSrv.Handler.(*chi.Mux)
	m.Get(pathHelloWorld, helloWorld(e))
	m.Get(pathAttestation, attestation.Handler(e.hashes))
	m.Get(autoAttestation, AutoAttestationHandler())

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
	hashes      *attestation.Hashes
	keyMaterial any
	ready, stop chan bool
	ParentCID   uint32
}

func (e *Enclave) Start() error {
	var err error
	errPrefix := "failed to start Nitro Enclave"

	if err = system.SetFdLimit(e.cfg.FdCur, e.cfg.FdMax); err != nil {
		log.Printf("Failed to set new file descriptor limit: %s", err)
	}

	if err = system.ConfigureLoIface(); err != nil {
		return fmt.Errorf("%s: %w", errPrefix, err)
	}

	// Start enclave-internal HTTP server.
	go system.RunNetworking(e.cfg, e.stop, ParentCID)

	// sleep until networking is setup, we can change this later for goroutines
	time.Sleep(3 * time.Second)

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
	log.Println("Public Web server started")
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

func AutoAttestationHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// create a 32 random nonce
		hardcodedNonce := []byte("123123231231213213213213241421121")

		/*
				ctx := context.TODO()
			log.Println("starting kms request")
			cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-2"))
			if err != nil {
				log.Println(err)
			}
		*/

		enclaveHandle, err := enclave.GetOrInitializeHandle()
		if err != nil {
			log.Println(err)
		}

		// edgebit method to get the attestation document
		attestationDocument, err := enclaveHandle.Attest(enclave.AttestationOptions{})
		if err != nil {
			log.Println(err)
		}

		log.Printf("Attestation Document: %s", len(attestationDocument))

		myPCRs, err := verifyAttestation(attestationDocument)
		if err != nil {
			log.Fatalf("Failed to verify attestation: %v", err)
		}

		// Verify that the PCR values match the expected values.
		// It will always work in this example, but in a real application you should be getting the value from another instance

		// nitriding method to get the attestation document
		rawAttDoc, err := attestation.Attest(hardcodedNonce, nil, nil)
		if err != nil {
			log.Fatalf("Failed to attest: %v", err)
		}

		res, err := nitrite.Verify(rawAttDoc, nitrite.VerifyOptions{})
		if err != nil {
			log.Fatalf("Failed to verify attestation: %v", err)
		}

		log.Printf("Attestation Document: %s", res.Document.Digest)

		if string(res.Document.Nonce) == string(hardcodedNonce) {
			log.Printf("nonce matches: %s ", hardcodedNonce)
		}

		result := attestation.ArePCRsIdentical(myPCRs, res.Document.PCRs)
		log.Printf("PCR values match: %v", result)

		rexs := ""
		for i, h := range res.Document.PCRs {
			log.Printf("PCR %d: %x", i, string(h))
			rexs += fmt.Sprintf(" -   PCR %d: %x", i, string(h))
		}

		rexs = rexs + " digest   " + res.Document.Digest + " public key  " + string(res.Document.PublicKey) + "  moduleID   " + res.Document.ModuleID

		/*

			kmsClient := kms.NewFromConfig(cfg)
			dataKeyRes, err := kmsClient.GenerateDataKey(context.Background(), &kms.GenerateDataKeyInput{
				KeyId:   aws.String("arn:aws:kms:us-east-2:832540076233:key/fe8fb5fb-8399-4e6a-8633-a00ad54b2e16"),
				KeySpec: types.DataKeySpecAes256,
				Recipient: &types.RecipientInfoType{
					AttestationDocument:    attestationDocument,
					KeyEncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
				},
			})
			if err != nil {
				log.Fatalln("error generating datakey", err)
			}

			log.Println("generated data key")
			log.Println(dataKeyRes.CiphertextForRecipient)

			if dataKeyRes.CiphertextForRecipient == nil {
				log.Fatalln("nil")
			}

			key, err := enclaveHandle.DecryptKMSEnvelopedKey(dataKeyRes.CiphertextForRecipient)
			if err != nil {
				log.Fatalln(err)
			}

			log.Printf("key: %v", key)

		*/

		w.Write([]byte(rexs))
		w.WriteHeader(http.StatusOK)
	}
}

func verifyAttestation(attestation []byte) (map[uint][]byte, error) {
	res, err := nitrite.Verify(attestation,
		nitrite.VerifyOptions{
			CurrentTime: time.Now(),
		})

	if nil != err {
		return nil, err
	}

	resJSON := ""

	if nil != res {
		enc, err := json.Marshal(res.Document)
		if nil != err {
			log.Fatalln(err)
		}

		resJSON = string(enc)
	}

	if nil != err {
		log.Fatalln("Attestation verification failed with error %v\n", err)
	}

	log.Printf("%v\n", resJSON)

	return res.Document.PCRs, nil
}
