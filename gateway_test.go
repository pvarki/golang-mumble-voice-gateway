package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

const (
	testOrigin  = "https://mtls.test"
	testTraefik = "traefik.traefik-system.serviceaccount.identity.linkerd.cluster.local"
)

type issued struct {
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey
}

func issue(t *testing.T, cn string, parent *issued, ca bool, usage x509.ExtKeyUsage, dns ...string) *issued {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  ca,
		BasicConstraintsValid: true,
		DNSNames:              dns,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	if !ca {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{usage}
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &issued{cert: cert, der: der, key: key}
}

func (i *issued) tls() tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{i.der}, PrivateKey: i.key}
}

func pool(certs ...*issued) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c.cert)
	}
	return p
}

// world is a platform CA with Murmur's certificate and a user, and the gateway's own CA.
type world struct {
	platform, murmur, user, gatewayCA, gateway *issued
}

func newWorld(t *testing.T) *world {
	platform := issue(t, "Platform CA", nil, true, 0)
	gatewayCA := issue(t, "Voice Gateway CA", nil, true, 0)
	// About one leaf in twenty has no "+" in its base64. The user's always has one, so every test forwards the
	// character that query unescaping would turn into a space.
	user := issue(t, "ALPHA 1", platform, false, x509.ExtKeyUsageClientAuth)
	for !strings.Contains(forwarded(user.der), "+") {
		user = issue(t, "ALPHA 1", platform, false, x509.ExtKeyUsageClientAuth)
	}
	return &world{
		platform:  platform,
		murmur:    issue(t, "tak.test", platform, false, x509.ExtKeyUsageServerAuth, "tak.test"),
		user:      user,
		gatewayCA: gatewayCA,
		gateway:   issue(t, "voice-gateway", gatewayCA, false, x509.ExtKeyUsageClientAuth),
	}
}

// fakeMurmur accepts one gateway connection, requiring the gateway CA's certificate, and hands it over.
func (w *world) fakeMurmur(t *testing.T) (string, <-chan *tls.Conn) {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{w.murmur.tls()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool(w.gatewayCA),
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	conns := make(chan *tls.Conn, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		tc := c.(*tls.Conn)
		if tc.Handshake() == nil {
			conns <- tc
		}
	}()
	return listener.Addr().String(), conns
}

func (w *world) gatewayServer(t *testing.T, murmurAddr string) *httptest.Server {
	t.Helper()
	g, err := NewGateway(Config{
		Origin:          testOrigin,
		TraefikIdentity: testTraefik,
		MurmurAddr:      murmurAddr,
		MurmurTLS: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			ServerName:   "tak.test",
			RootCAs:      pool(w.platform),
			Certificates: []tls.Certificate{w.gateway.tls()},
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(newMux(g, http.NotFoundHandler()))
	t.Cleanup(server.Close)
	return server
}

func ticketFor(username string, leaf []byte) string {
	payload, _ := json.Marshal(map[string]any{"u": username, "c": base64.RawURLEncoding.EncodeToString(leaf), "e": 1})
	return base64.RawURLEncoding.EncodeToString(payload) + ".c2ln"
}

// As Traefik sends it: the base64 as is, "+" and "/" included
func forwarded(der []byte) string {
	return base64.StdEncoding.EncodeToString(der)
}

func browserHeaders(der []byte) http.Header {
	h := http.Header{}
	h.Set("Origin", testOrigin)
	h.Set("l5d-client-id", testTraefik)
	h.Set(forwardedHdr, forwarded(der))
	return h
}

func dial(t *testing.T, server *httptest.Server, h http.Header) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/ws", &websocket.DialOptions{HTTPHeader: h})
}

func readFrame(t *testing.T, r io.Reader) (uint16, []byte) {
	t.Helper()
	header := make([]byte, headerLen)
	if _, err := io.ReadFull(r, header); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, binary.BigEndian.Uint32(header[2:]))
	if _, err := io.ReadFull(r, payload); err != nil {
		t.Fatal(err)
	}
	return binary.BigEndian.Uint16(header), payload
}

// pbFields decodes a flat protobuf message into field number -> raw values (varints as decimal bytes).
func pbFields(t *testing.T, b []byte) map[int][]byte {
	t.Helper()
	out := map[int][]byte{}
	varint := func() uint64 {
		var v uint64
		for shift := 0; ; shift += 7 {
			c := b[0]
			b = b[1:]
			v |= uint64(c&0x7f) << shift
			if c < 0x80 {
				return v
			}
		}
	}
	for len(b) > 0 {
		tag := varint()
		switch tag & 7 {
		case 0:
			out[int(tag>>3)] = []byte(big.NewInt(int64(varint())).String())
		case 2:
			n := varint()
			out[int(tag>>3)] = b[:n]
			b = b[n:]
		default:
			t.Fatalf("wire type %d", tag&7)
		}
	}
	return out
}

func TestSessionLogsInWithTheTicketAndRelaysBothWays(t *testing.T) {
	w := newWorld(t)
	addr, conns := w.fakeMurmur(t)
	server := w.gatewayServer(t, addr)
	conn, _, err := dial(t, server, browserHeaders(w.user.der))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.CloseNow() }()
	ticket := ticketFor("ALPHA_1---web-1", w.user.der)
	ctx := context.Background()
	if err := conn.Write(ctx, websocket.MessageText, []byte(ticket)); err != nil {
		t.Fatal(err)
	}
	murmur := <-conns
	defer func() { _ = murmur.Close() }()
	if got := murmur.ConnectionState().PeerCertificates[0].Subject.CommonName; got != "voice-gateway" {
		t.Fatalf("Murmur saw %q", got)
	}

	kind, version := readFrame(t, murmur)
	if kind != msgVersion || string(pbFields(t, version)[2]) != clientRelease || string(pbFields(t, version)[1]) != "66560" {
		t.Fatalf("version %d %v", kind, pbFields(t, version))
	}
	kind, auth := readFrame(t, murmur)
	fields := pbFields(t, auth)
	if kind != msgAuthenticate || string(fields[1]) != "ALPHA_1---web-1" || string(fields[2]) != ticket || string(fields[5]) != "1" {
		t.Fatalf("authenticate %d %v", kind, fields)
	}

	if _, err := murmur.Write(frame(5, []byte("sync"))); err != nil { // ServerSync
		t.Fatal(err)
	}
	msgKind, msg, err := conn.Read(ctx)
	if err != nil || msgKind != websocket.MessageBinary || !bytes.Equal(msg, frame(5, []byte("sync"))) {
		t.Fatalf("browser got %v %v %v", msgKind, msg, err)
	}

	for _, k := range []uint16{msgPing, msgUDPTunnel, msgUserState, msgPermissionQuery, msgRequestBlob} {
		if err := conn.Write(ctx, websocket.MessageBinary, frame(k, []byte{1, 2})); err != nil {
			t.Fatal(err)
		}
		if got, payload := readFrame(t, murmur); got != k || !bytes.Equal(payload, []byte{1, 2}) {
			t.Fatalf("murmur got %d %v", got, payload)
		}
	}
}

func TestBrowserCannotAuthenticateAgainOrSendOtherTypes(t *testing.T) {
	for _, msg := range [][]byte{
		frame(msgAuthenticate, authenticateMessage("BRAVO_2---web-1", "x")),
		frame(msgVersion, nil),
		frame(11, []byte("text")),      // TextMessage
		frame(msgPing, []byte{1})[:6],  // header claims a byte it lacks
		{0, 3},                         // shorter than a header
		append(frame(msgPing, nil), 9), // trailing junk
	} {
		w := newWorld(t)
		addr, conns := w.fakeMurmur(t)
		conn, _, err := dial(t, w.gatewayServer(t, addr), browserHeaders(w.user.der))
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		_ = conn.Write(ctx, websocket.MessageText, []byte(ticketFor("ALPHA_1---web-1", w.user.der)))
		murmur := <-conns
		readFrame(t, murmur)
		readFrame(t, murmur)
		_ = conn.Write(ctx, websocket.MessageBinary, msg)
		_, _, err = conn.Read(ctx)
		if websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
			t.Fatalf("%v: expected a policy close, got %v", msg, err)
		}
		_ = murmur.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, err := murmur.Read(make([]byte, 64)); err == nil {
			t.Fatalf("%v reached Murmur (%d bytes)", msg, n)
		}
		_ = conn.CloseNow()
	}
}

func TestRefusesTicketsThatAreNotThisConnections(t *testing.T) {
	w := newWorld(t)
	other := issue(t, "BRAVO 2", w.platform, false, x509.ExtKeyUsageClientAuth)
	for name, ticket := range map[string]string{
		"another certificate": ticketFor("BRAVO_2---web-1", other.der),
		"a phone slot":        ticketFor("ALPHA_1---vs1", w.user.der),
		"garbage":             "not a ticket",
		"bad base64":          "!!.x",
		"not json":            base64.RawURLEncoding.EncodeToString([]byte("[")) + ".x",
		"no leaf":             base64.RawURLEncoding.EncodeToString([]byte(`{"u":"A---web-1"}`)) + ".x",
	} {
		addr, conns := w.fakeMurmur(t)
		conn, _, err := dial(t, w.gatewayServer(t, addr), browserHeaders(w.user.der))
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		_ = conn.Write(ctx, websocket.MessageText, []byte(ticket))
		if _, _, err := conn.Read(ctx); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
			t.Fatalf("%s: got %v", name, err)
		}
		select {
		case <-conns:
			t.Fatalf("%s: Murmur was dialled", name)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func TestForwardedLeafEscaped(t *testing.T) {
	der := bytes.Repeat([]byte{0xfb, 0xff}, 40) // base64 full of "+" and "/"
	for _, value := range []string{forwarded(der), url.QueryEscape(forwarded(der))} {
		r := httptest.NewRequest(http.MethodGet, "/ws", nil)
		r.Header.Set(forwardedHdr, value+",Q0E=")
		if !bytes.Equal(forwardedLeaf(r), der) {
			t.Fatalf("%q", value)
		}
	}
}

func TestTicketMustBeTextAndArrive(t *testing.T) {
	w := newWorld(t)
	addr, _ := w.fakeMurmur(t)
	server := w.gatewayServer(t, addr)
	conn, _, _ := dial(t, server, browserHeaders(w.user.der))
	ctx := context.Background()
	_ = conn.Write(ctx, websocket.MessageBinary, []byte(ticketFor("ALPHA_1---web-1", w.user.der)))
	if _, _, err := conn.Read(ctx); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("binary ticket: %v", err)
	}
	conn, _, _ = dial(t, server, browserHeaders(w.user.der))
	_ = conn.CloseNow() // leaves without a ticket
}

func TestRefusedBeforeTheUpgrade(t *testing.T) {
	w := newWorld(t)
	addr, _ := w.fakeMurmur(t)
	server := w.gatewayServer(t, addr)
	cases := map[string]func(http.Header){
		"not through Traefik": func(h http.Header) {
			h.Set("l5d-client-id", "rmapi.opendefence-system.serviceaccount.identity.linkerd.cluster.local")
		},
		"not meshed":         func(h http.Header) { h.Del("l5d-client-id") },
		"foreign origin":     func(h http.Header) { h.Set("Origin", "https://evil.test") },
		"no origin":          func(h http.Header) { h.Del("Origin") },
		"no certificate":     func(h http.Header) { h.Del(forwardedHdr) },
		"broken certificate": func(h http.Header) { h.Set(forwardedHdr, "%%%") },
		"not base64":         func(h http.Header) { h.Set(forwardedHdr, "***") },
		"spaces for pluses": func(h http.Header) {
			value := h.Get(forwardedHdr)
			if !strings.Contains(value, "+") {
				t.Fatal("spaces for pluses: the certificate has no + to swap")
			}
			h.Set(forwardedHdr, strings.ReplaceAll(value, "+", " "))
		},
	}
	for name, change := range cases {
		h := browserHeaders(w.user.der)
		change(h)
		_, resp, err := dial(t, server, h)
		if err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s: %v %v", name, resp, err)
		}
	}
}

func TestMurmurUnreachableOrClosing(t *testing.T) {
	w := newWorld(t)
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := listener.Addr().String()
	_ = listener.Close()
	conn, _, _ := dial(t, w.gatewayServer(t, addr), browserHeaders(w.user.der))
	ctx := context.Background()
	_ = conn.Write(ctx, websocket.MessageText, []byte(ticketFor("ALPHA_1---web-1", w.user.der)))
	if _, _, err := conn.Read(ctx); websocket.CloseStatus(err) != websocket.StatusTryAgainLater {
		t.Fatalf("unreachable: %v", err)
	}

	addr, conns := w.fakeMurmur(t)
	conn, _, _ = dial(t, w.gatewayServer(t, addr), browserHeaders(w.user.der))
	_ = conn.Write(ctx, websocket.MessageText, []byte(ticketFor("ALPHA_1---web-1", w.user.der)))
	murmur := <-conns
	readFrame(t, murmur)
	readFrame(t, murmur)
	huge := make([]byte, headerLen)
	binary.BigEndian.PutUint32(huge[2:], maxFrame+1)
	_, _ = murmur.Write(huge)
	if _, _, err := conn.Read(ctx); websocket.CloseStatus(err) != websocket.StatusNormalClosure {
		t.Fatalf("oversized: %v", err)
	}

	addr, conns = w.fakeMurmur(t)
	conn, _, _ = dial(t, w.gatewayServer(t, addr), browserHeaders(w.user.der))
	_ = conn.Write(ctx, websocket.MessageText, []byte(ticketFor("ALPHA_1---web-1", w.user.der)))
	murmur = <-conns
	readFrame(t, murmur)
	_, _ = murmur.Write(frame(5, []byte("abc"))[:7]) // cut off mid-message
	_ = murmur.Close()
	if _, _, err := conn.Read(ctx); websocket.CloseStatus(err) != websocket.StatusNormalClosure {
		t.Fatalf("murmur closed: %v", err)
	}
}

func TestNewGatewayWantsAnHTTPSOrigin(t *testing.T) {
	for _, origin := range []string{"", "http://mtls.test", "https://", "https://mtls.test/path", "::"} {
		if _, err := NewGateway(Config{Origin: origin}, nil); err == nil {
			t.Fatalf("%q accepted", origin)
		}
	}
}

func TestHealthz(t *testing.T) {
	rec := httptest.NewRecorder()
	newMux(http.NotFoundHandler(), http.NotFoundHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatal(rec.Code)
	}
}

func TestReadyzFollowsTheProxy(t *testing.T) {
	status := http.StatusOK
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close() // nothing listens there: a pod the injector missed
	defer proxy.Close()
	ask := func(proxyReady string) int {
		rec := httptest.NewRecorder()
		mux := newMux(http.NotFoundHandler(), readyz(proxyReady, &http.Client{Timeout: time.Second}))
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		return rec.Code
	}
	if code := ask(proxy.URL); code != http.StatusNoContent {
		t.Fatal("ready proxy:", code)
	}
	status = http.StatusServiceUnavailable
	if code := ask(proxy.URL); code != http.StatusServiceUnavailable {
		t.Fatal("proxy not ready:", code)
	}
	if code := ask(gone.URL); code != http.StatusServiceUnavailable {
		t.Fatal("no proxy:", code)
	}
	if code := ask(""); code != http.StatusNoContent {
		t.Fatal("unchecked:", code)
	}
}

func writePEM(t *testing.T, dir, name, kind string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfig(t *testing.T) {
	w := newWorld(t)
	dir := t.TempDir()
	key, _ := x509.MarshalECPrivateKey(w.gateway.key)
	t.Setenv("GATEWAY_CERT", writePEM(t, dir, "tls.crt", "CERTIFICATE", w.gateway.der))
	t.Setenv("GATEWAY_KEY", writePEM(t, dir, "tls.key", "EC PRIVATE KEY", key))
	t.Setenv("GATEWAY_MURMUR_CA", writePEM(t, dir, "ca.pem", "CERTIFICATE", w.platform.der))
	t.Setenv("GATEWAY_ORIGIN", testOrigin)
	t.Setenv("GATEWAY_MURMUR_NAME", "tak.test")
	cfg, err := loadConfig()
	if err != nil || cfg.MurmurTLS.ServerName != "tak.test" || cfg.TraefikIdentity != testTraefik ||
		cfg.MurmurAddr != "murmur.app-mumble.svc.cluster.local:64738" {
		t.Fatalf("%+v %v", cfg, err)
	}

	steps := []struct {
		name, value, want string
	}{
		{"GATEWAY_MURMUR_NAME", "", "GATEWAY_MURMUR_NAME"},
		{"GATEWAY_MURMUR_CA", writePEM(t, dir, "empty.pem", "NOTHING", nil), "no certificates"},
		{"GATEWAY_MURMUR_CA", filepath.Join(dir, "missing"), "Murmur's CA"},
		{"GATEWAY_KEY", filepath.Join(dir, "missing"), "gateway certificate"},
		{"GATEWAY_ORIGIN", "", "GATEWAY_ORIGIN"},
	}
	for _, step := range steps {
		t.Setenv(step.name, step.value)
		if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), step.want) {
			t.Fatalf("%s=%q: %v", step.name, step.value, err)
		}
	}
}

func TestECSLogger(t *testing.T) {
	stdout := os.Stdout
	r, wr, _ := os.Pipe()
	os.Stdout = wr
	ecsLogger().WithGroup("g").Info("hello", "k", "v")
	os.Stdout = stdout
	_ = wr.Close()
	var line map[string]any
	if err := json.NewDecoder(r).Decode(&line); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"@timestamp", "log.level", "message", "ecs.version"} {
		if _, ok := line[key]; !ok {
			t.Fatalf("no %s in %v", key, line)
		}
	}
	if line["log.level"] != "info" || line["message"] != "hello" {
		t.Fatal(line)
	}
}

func TestEnv(t *testing.T) {
	t.Setenv("GATEWAY_TEST_X", "")
	if env("GATEWAY_TEST_X", "d") != "d" {
		t.Fatal("fallback")
	}
}

func TestEachDialReadsTheGatewayCertificateAgain(t *testing.T) {
	w := newWorld(t)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	install := func(c *issued) {
		key, _ := x509.MarshalECPrivateKey(c.key)
		writePEM(t, dir, "tls.crt", "CERTIFICATE", c.der)
		writePEM(t, dir, "tls.key", "EC PRIVATE KEY", key)
	}
	murmurTLS := &tls.Config{
		MinVersion:           tls.VersionTLS12,
		ServerName:           "tak.test",
		RootCAs:              pool(w.platform),
		GetClientCertificate: clientCertificate(certFile, keyFile),
	}
	presented := func() []byte {
		t.Helper()
		addr, conns := w.fakeMurmur(t)
		conn, err := (&tls.Dialer{Config: murmurTLS}).DialContext(context.Background(), "tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		select {
		case murmur := <-conns:
			defer func() { _ = murmur.Close() }()
			return murmur.ConnectionState().PeerCertificates[0].Raw
		case <-time.After(5 * time.Second):
			t.Fatal("Murmur refused the gateway's certificate")
			return nil
		}
	}

	install(w.gateway)
	if !bytes.Equal(presented(), w.gateway.der) {
		t.Fatal("the first dial did not present the installed certificate")
	}
	renewed := issue(t, "voice-gateway", w.gatewayCA, false, x509.ExtKeyUsageClientAuth)
	install(renewed) // as cert-manager renews it, without a restart
	if !bytes.Equal(presented(), renewed.der) {
		t.Fatal("the next dial still presented the old certificate")
	}
	if err := os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	if _, err := murmurTLS.GetClientCertificate(nil); err == nil || !strings.Contains(err.Error(), "gateway certificate") {
		t.Fatalf("a missing key: %v", err)
	}
}

func TestBrowserMessagesStaySmall(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	addr, _ := w.fakeMurmur(t)
	conn, _, err := dial(t, w.gatewayServer(t, addr), browserHeaders(w.user.der))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Write(ctx, websocket.MessageText, bytes.Repeat([]byte("a"), maxTicket+1))
	if _, _, err := conn.Read(ctx); websocket.CloseStatus(err) != websocket.StatusMessageTooBig {
		t.Fatalf("oversized ticket: %v", err)
	}

	addr, conns := w.fakeMurmur(t)
	conn, _, err = dial(t, w.gatewayServer(t, addr), browserHeaders(w.user.der))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Write(ctx, websocket.MessageText, []byte(ticketFor("ALPHA_1---web-1", w.user.der)))
	murmur := <-conns
	defer func() { _ = murmur.Close() }()
	readFrame(t, murmur)
	readFrame(t, murmur)
	_ = conn.Write(ctx, websocket.MessageBinary, frame(msgUDPTunnel, make([]byte, maxBrowser)))
	if _, _, err := conn.Read(ctx); websocket.CloseStatus(err) != websocket.StatusMessageTooBig {
		t.Fatalf("oversized message: %v", err)
	}
}
