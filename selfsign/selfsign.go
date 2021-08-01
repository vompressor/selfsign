package selfsign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"time"
)

type SelfSignConfig struct {
	Country,
	Organization,
	OrgUnit,
	StreetAddress,
	PostalCode,
	Locality,
	Province []string
	CommonName string

	IP    []net.IP
	DNS   []string
	Email []string
	URI   []*url.URL

	NotAfterDays int
}

func SelfSignCrt(config SelfSignConfig) (cert, key []byte, err error) {
	now := time.Now()
	t := x509.Certificate{
		Subject: pkix.Name{
			Organization:       config.Organization,
			Country:            config.Country,
			OrganizationalUnit: config.OrgUnit,
			Locality:           config.Locality,
			Province:           config.Province,
			StreetAddress:      config.StreetAddress,
			PostalCode:         config.PostalCode,
			CommonName:         config.CommonName,
		},
		NotBefore: now,

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		IsCA: true,

		IPAddresses:    config.IP,
		DNSNames:       config.DNS,
		URIs:           config.URI,
		EmailAddresses: config.Email,
		NotAfter:       now.Add(time.Duration(config.NotAfterDays) * time.Hour * 24),
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	t.SerialNumber, _ = rand.Int(rand.Reader, serialNumberLimit)

	derBytes, err := x509.CreateCertificate(rand.Reader, &t, &t, &priv.PublicKey, priv)
	if err != nil {
		return
	}

	cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	x, _ := x509.MarshalECPrivateKey(priv)
	key = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x})
	return
}

func WritePEM(
	certPath, keyPath string,
	cert, key []byte,
) error {
	if f, err := os.Create(certPath); err != nil {
		return err
	} else {
		if _, err := f.Write(cert); err != nil {
			return err
		}
		f.Close()
	}

	if f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600); err != nil {
		return err
	} else {
		if _, err := f.Write(key); err != nil {
			return err
		}
		f.Close()
	}
	return nil
}
