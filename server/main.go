package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"os"
)

func main() {

	rootCaCert, err := os.ReadFile("rootCA.crt")
	if err != nil {
		log.Fatal(err)
	}

	rootCaCertPool := x509.NewCertPool()
	rootCaCertPool.AppendCertsFromPEM(rootCaCert)

	tlsConfig := &tls.Config{
		ClientCAs:  rootCaCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			clientCert, err := os.ReadFile("../client/client-cert.pem")
			if err != nil {
				return err
			}

			clientCertPem, cr := pem.Decode(clientCert)
			if len(cr) != 0 {
				return errors.New("more data in clientCert than expected")
			}

			receivedCert := verifiedChains[0][0].Raw

			if len(receivedCert) != len(clientCertPem.Bytes) {
				return errors.New("certificate length does not match")
			}

			for i, v := range receivedCert {
				if v != clientCertPem.Bytes[i] {
					return errors.New("certificate content does not match")
				}
			}

			return nil

		},
	}

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
		Handler:   http.HandlerFunc(helloHandler),
	}

	http.HandleFunc("/hello", helloHandler)
	log.Fatal(server.ListenAndServeTLS("server-cert.pem", "server-key.pem"))
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s connected", r.TLS.PeerCertificates[0].Subject)
	w.Write([]byte("Hello " + r.TLS.PeerCertificates[0].Subject.String()))
}
