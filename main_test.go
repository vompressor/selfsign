package main_test

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"testing"

	"github.com/vompressor/selfsign/selfsign"
)

func TestSelfSign(t *testing.T) {
	conf := selfsign.SelfSignConfig{
		Organization: []string{"test"},
		CommonName:   "test",
		IP:           []net.IP{net.ParseIP("127.0.0.1")},
		DNS:          []string{"localhost"},
		NotAfterDays: 3650,
	}

	cert, key, err := selfsign.SelfSignCrt(conf)
	if err != nil {
		t.Fatal(err.Error())
	}

	err = selfsign.WritePEM("cert.pem", "key.pem", cert, key)
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestTlsDial(t *testing.T) {

	p, _ := ioutil.ReadFile("cert.pem")

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(p)

	tc, err := tls.Dial("tcp", "127.0.0.1:41111", &tls.Config{
		RootCAs: pool,
	})

	if err != nil {
		t.Fatal(err.Error())
	}
	defer tc.Close()

	tc.Write([]byte("hello tls"))

	buf := make([]byte, 512)
	n, _ := tc.Read(buf)

	t.Log(string(buf[:n]))
}
