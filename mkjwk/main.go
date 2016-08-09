// mkjwk generates a private key and its JWK with a random ID in the current directory
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"log"
	"os"

	jose "gopkg.in/square/go-jose.v2"
)

var (
	keyName = flag.String("key.name", "rsa_key", "name of the generated key")
	keySize = flag.Int("key.size", 2048, "size of the RSA key")
)

func main() {
	flag.Parse()
	k, err := rsa.GenerateKey(rand.Reader, *keySize)
	if err != nil {
		log.Fatal(err)
	}

	jwk := jose.JSONWebKey{
		Key:       &k.PublicKey,
		KeyID:     randString(),
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
	jwkBytes, err := jwk.MarshalJSON()
	if err != nil {
		log.Fatal(err)
	}

	kf, err := os.Create(*keyName)
	if err != nil {
		log.Fatal(err)
	}
	blk := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	if err := pem.Encode(kf, blk); err != nil {
		log.Fatal(err)
	}

	jwkf, err := os.Create(*keyName + ".jwk")
	if err != nil {
		log.Fatal(err)
	}

	if _, err := jwkf.Write(jwkBytes); err != nil {
		log.Fatal(err)
	}
}

func randString() string {
	h := sha256.New()
	b := make([]byte, 1024)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	if _, err := h.Write(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}
