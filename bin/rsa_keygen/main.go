package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log"
	"moknito/token"
)

func main() {
	log.Println("(!) BE CAREFUL BECAUSE THE KEYS ARE PRINTED AS FOLLOW (!)")

	privateKey, err := rsa.GenerateKey(rand.Reader, token.RSA_PRIV_KEY_LEN)
	if err != nil {
		log.Fatalln(err)
	}

	privBuf := new(bytes.Buffer)
	{
		privBlock := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		}
		if err := pem.Encode(privBuf, privBlock); err != nil {
			log.Fatalln(err)
		}
	}
	encPriv := base64.StdEncoding.EncodeToString(privBuf.Bytes())

	pubBuf := new(bytes.Buffer)
	{
		pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			log.Fatal(err)
		}

		pubBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBytes,
		}
		if err := pem.Encode(pubBuf, pubBlock); err != nil {
			log.Fatalln(err)
		}
	}
	encPub := base64.StdEncoding.EncodeToString(pubBuf.Bytes())

	log.Printf("\n%s\n", encPriv)
	log.Printf("\n%s\n", encPub)
}
