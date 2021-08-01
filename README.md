# selfsign
Create self signed certification!   

## run code
```
// Create certification
$ go test -run TestSelfSign github.com/vompressor/selfsign -v

// Created cert.pem, key.pem
$ tree
.
├── cert.pem
├── go.mod
├── key.pem
├── LICENSE
├── main.go
├── main_test.go
├── README.md
└── selfsign
    └── selfsign.go
```
```
// build and run tls server
$ go build -o main
$ ./main&

// run tls client
$ go test -run TestTlsDial github.com/vompressor/selfsign -v
```

## Example
### Create certification
```
// create self signed certification
// code main

conf := selfsign.SelfSignConfig{
    Organization: []string{"test"},
    CommonName:   "test",
    IP:           []net.IP{net.ParseIP("127.0.0.1")},
    DNS:          []string{"localhost"},
    NotAfterDays: 3650,
}

cert, key, err := selfsign.SelfSignCrt(conf)
if err != nil {
    log.Fatal(err.Error())
}

err = selfsign.WritePEM("cert.pem", "key.pem", cert, key)
if err != nil {
    log.Fatal(err.Error())
}
// created self signed certification!
```

### tls socket
```
// server code main

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
// created tls socket!
```
```
// client code main

// certification self signed,
// so you need to add server certification at CA 
p, err := ioutil.ReadFile("cert.pem")
if err != nil {
    log.Fatal(err.Error())
}

pool := x509.NewCertPool()
pool.AppendCertsFromPEM(p)

tc, err := tls.Dial("tcp", "127.0.0.1:41111", &tls.Config{
    RootCAs: pool,
})

if err != nil {
    log.Fatal(err.Error())
}
defer tc.Close()
// created tls socket!
```