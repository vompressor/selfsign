package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
)

func main() {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}}

	config.MinVersion = tls.VersionTLS13
	config.CipherSuites = []uint16{
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	}

	config.Rand = rand.Reader
	service := "localhost:41111"
	listener, err := tls.Listen("tcp", service, &config)
	if err != nil {
		log.Fatalf("server: listen: %s", err)
	}
	defer listener.Close()
	log.Print("server: listening")

	conn, err := listener.Accept()
	if err != nil {
		log.Printf("server: accept: %s", err)
		return
	}
	defer conn.Close()
	log.Printf("server: accepted from %s", conn.RemoteAddr())
	tlscon, ok := conn.(*tls.Conn)
	if ok {
		log.Print("ok=true")
		state := tlscon.ConnectionState()
		for _, v := range state.PeerCertificates {
			log.Print(x509.MarshalPKIXPublicKey(v.PublicKey))
		}

		handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 512)
	for {
		log.Print("server: conn: waiting")
		n, err := conn.Read(buf)
		if err != nil {
			if err != nil {
				log.Printf("server: conn: read: %s", err)
			}
			break
		}
		log.Printf("server: conn: echo %q\n", string(buf[:n]))
		n, err = conn.Write(buf[:n])
		log.Printf("server: conn: wrote %d bytes", n)

		if err != nil {
			log.Printf("server: write: %s", err)
			break
		}
	}
	log.Println("server: conn: closed")
}
