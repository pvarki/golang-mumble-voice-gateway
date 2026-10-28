// The voice gateway lets browsers into Murmur (VOICE-PLAN §4.10). Browsers cannot speak Mumble's TLS with a
// client certificate, so the gateway speaks it for them: it logs in with its own certificate and a ticket that
// mumblermapi signed for the browser's user, and murmur-agent checks that user's certificate from the ticket.
//
// The gateway mints nothing and asserts nothing: a session's name and certificate come from the ticket, and
// the gateway only checks that the ticket belongs to the client certificate Traefik verified on this connection.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/coder/websocket"
)

// Mumble's TCP message types (Mumble.proto order)
const (
	msgVersion         = 0
	msgUDPTunnel       = 1
	msgAuthenticate    = 2
	msgPing            = 3
	msgUserState       = 9
	msgPermissionQuery = 20
	msgRequestBlob     = 23
)

const (
	headerLen = 6
	// Murmur's own limit on a message is 8 MiB; nothing a voice client needs comes close to this.
	maxFrame     = 1 << 20
	maxTicket    = 8192
	maxBrowser   = 64 << 10 // a browser sends voice and small control messages; a larger one ends the session
	ticketWait   = 10 * time.Second
	dialTimeout  = 10 * time.Second
	forwardedHdr = "X-Forwarded-Tls-Client-Cert"
	// Announcing 1.4 keeps Murmur on the legacy voice packet format, which the browser decodes.
	clientVersion = 1<<16 | 4<<8
	clientRelease = "OpenDefence browser"
)

// What a browser may send once logged in: voice, keepalives, moving itself between nets, and asking what it
// may do. Version and Authenticate come from the gateway only, and only once.
var fromBrowser = map[uint16]bool{
	msgUDPTunnel:       true,
	msgPing:            true,
	msgUserState:       true,
	msgPermissionQuery: true,
	msgRequestBlob:     true,
}

var webUsername = regexp.MustCompile(`^\S+---web-[1-9]$`)

// Config is where Murmur is and what the gateway trusts.
type Config struct {
	Origin          string      // the only page origin allowed to open a session, https://mtls.<domain>
	TraefikIdentity string      // the Linkerd identity every request must arrive from
	MurmurAddr      string      // host:port
	MurmurTLS       *tls.Config // Murmur's name and CA, and the gateway's own client certificate
}

// Gateway serves the browser WebSocket.
type Gateway struct {
	cfg        Config
	originHost string
	log        *slog.Logger
}

// NewGateway checks the configured origin and builds the handler.
func NewGateway(cfg Config, log *slog.Logger) (*Gateway, error) {
	origin, err := url.Parse(cfg.Origin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.Path != "" {
		return nil, fmt.Errorf("origin %q is not https://<host>", cfg.Origin)
	}
	return &Gateway{cfg: cfg, originHost: origin.Host, log: log}, nil
}

type claims struct {
	Username string `json:"u"`
	Leaf     string `json:"c"`
}

// ticketClaims reads the username and leaf from a ticket without checking its signature: murmur-agent does
// that. The gateway only needs to know whose ticket it is.
func ticketClaims(ticket string) (claims, []byte, error) {
	var c claims
	head, _, ok := strings.Cut(ticket, ".")
	if !ok || len(ticket) > maxTicket {
		return c, nil, errors.New("malformed ticket")
	}
	data, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return c, nil, errors.New("malformed ticket")
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, nil, errors.New("malformed ticket")
	}
	leaf, err := base64.RawURLEncoding.DecodeString(c.Leaf)
	if err != nil || len(leaf) == 0 {
		return c, nil, errors.New("malformed ticket")
	}
	if !webUsername.MatchString(c.Username) {
		return c, nil, errors.New("ticket is not for a web slot")
	}
	return c, leaf, nil
}

// forwardedLeaf is the client certificate Traefik verified: PEM bodies, leaf first, comma-separated. Path
// unescaping keeps a literal "+" of the base64, where query unescaping would turn it into a space.
func forwardedLeaf(r *http.Request) []byte {
	value, err := url.PathUnescape(r.Header.Get(forwardedHdr))
	if err != nil {
		return nil
	}
	first, _, _ := strings.Cut(value, ",")
	der, err := base64.StdEncoding.DecodeString(first)
	if err != nil {
		return nil
	}
	return der
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("l5d-client-id") != g.cfg.TraefikIdentity {
		g.log.Warn("refused: not through the edge", "peer", r.Header.Get("l5d-client-id"))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Header.Get("Origin") != g.cfg.Origin {
		g.log.Warn("refused: foreign origin", "origin", r.Header.Get("Origin"))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	leaf := forwardedLeaf(r)
	if len(leaf) == 0 {
		g.log.Warn("refused: no client certificate")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{g.originHost}})
	if err != nil {
		return // Accept has answered
	}
	conn.SetReadLimit(maxTicket)
	defer func() { _ = conn.CloseNow() }()
	if err := g.session(r.Context(), conn, leaf); err != nil {
		g.log.Info("session ended", "reason", err.Error())
	}
}

func (g *Gateway) session(ctx context.Context, conn *websocket.Conn, leaf []byte) error {
	waitCtx, cancel := context.WithTimeout(ctx, ticketWait)
	kind, first, err := conn.Read(waitCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("no ticket: %w", err)
	}
	if kind != websocket.MessageText {
		_ = conn.Close(websocket.StatusPolicyViolation, "send the ticket first")
		return errors.New("ticket was not text")
	}
	ticket := string(first)
	c, ticketLeaf, err := ticketClaims(ticket)
	if err != nil {
		_ = conn.Close(websocket.StatusPolicyViolation, err.Error())
		return err
	}
	if !bytes.Equal(ticketLeaf, leaf) {
		g.log.Warn("refused: ticket belongs to another certificate", "username", c.Username)
		_ = conn.Close(websocket.StatusPolicyViolation, "ticket belongs to another certificate")
		return errors.New("ticket leaf mismatch")
	}
	conn.SetReadLimit(maxBrowser)

	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: dialTimeout}, Config: g.cfg.MurmurTLS}
	raw, err := dialer.DialContext(ctx, "tcp", g.cfg.MurmurAddr)
	if err != nil {
		_ = conn.Close(websocket.StatusTryAgainLater, "voice server unreachable")
		return fmt.Errorf("dial murmur: %w", err)
	}
	murmur := raw.(*tls.Conn)
	defer func() { _ = murmur.Close() }()
	login, err := loginMessages(c.Username, ticket)
	if err != nil {
		return fmt.Errorf("log in: %w", err)
	}
	if _, err := murmur.Write(login); err != nil {
		return fmt.Errorf("log in: %w", err)
	}
	g.log.Info("session started", "username", c.Username)

	ctx, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan error, 2)
	go func() { done <- toBrowser(ctx, murmur, conn) }()
	go func() { done <- toMurmur(ctx, conn, murmur) }()
	err = <-done
	// Close before cancelling: a cancelled read drops the WebSocket without the close handshake.
	_ = murmur.Close()
	_ = conn.Close(websocket.StatusNormalClosure, "")
	return err
}

// toBrowser forwards each Murmur message, header included, as one binary WebSocket message.
func toBrowser(ctx context.Context, murmur io.Reader, conn *websocket.Conn) error {
	header := make([]byte, headerLen)
	for {
		if _, err := io.ReadFull(murmur, header); err != nil {
			return fmt.Errorf("murmur closed: %w", err)
		}
		size := binary.BigEndian.Uint32(header[2:])
		if size > maxFrame {
			return fmt.Errorf("murmur sent %d bytes in one message", size)
		}
		msg := make([]byte, headerLen+int(size))
		copy(msg, header)
		if _, err := io.ReadFull(murmur, msg[headerLen:]); err != nil {
			return fmt.Errorf("murmur closed: %w", err)
		}
		if err := conn.Write(ctx, websocket.MessageBinary, msg); err != nil {
			return fmt.Errorf("browser gone: %w", err)
		}
	}
}

// toMurmur forwards whole Mumble messages of the allowed types; anything else ends the session.
func toMurmur(ctx context.Context, conn *websocket.Conn, murmur io.Writer) error {
	for {
		kind, msg, err := conn.Read(ctx)
		if err != nil {
			return fmt.Errorf("browser gone: %w", err)
		}
		if kind != websocket.MessageBinary || len(msg) < headerLen ||
			int(binary.BigEndian.Uint32(msg[2:headerLen])) != len(msg)-headerLen {
			_ = conn.Close(websocket.StatusPolicyViolation, "one whole Mumble message per frame")
			return errors.New("malformed message from browser")
		}
		if kind := binary.BigEndian.Uint16(msg); !fromBrowser[kind] {
			_ = conn.Close(websocket.StatusPolicyViolation, "message type not allowed")
			return fmt.Errorf("browser sent message type %d", kind)
		}
		if _, err := murmur.Write(msg); err != nil {
			return fmt.Errorf("murmur gone: %w", err)
		}
	}
}

func frame(kind uint16, payload []byte) ([]byte, error) {
	n := len(payload)
	if n > maxFrame {
		return nil, fmt.Errorf("message type %d is %d bytes, over %d", kind, n, maxFrame)
	}
	msg := make([]byte, headerLen, headerLen+n)
	binary.BigEndian.PutUint16(msg, kind)
	binary.BigEndian.PutUint32(msg[2:], uint32(n))
	return append(msg, payload...), nil
}

// loginMessages are Version and Authenticate, logging in with the ticket as the password
func loginMessages(username, ticket string) ([]byte, error) {
	version, err := frame(msgVersion, versionMessage())
	if err != nil {
		return nil, err
	}
	auth, err := frame(msgAuthenticate, authenticateMessage(username, ticket))
	if err != nil {
		return nil, err
	}
	return append(version, auth...), nil
}

// Protobuf, by hand: the gateway writes two messages and parses none.
func pbVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func pbUint(b []byte, field, v uint64) []byte {
	return pbVarint(pbVarint(b, field<<3), v)
}

func pbString(b []byte, field uint64, s string) []byte {
	b = pbVarint(b, field<<3|2)
	return append(pbVarint(b, uint64(len(s))), s...)
}

func versionMessage() []byte {
	return pbString(pbUint(nil, 1, clientVersion), 2, clientRelease)
}

func authenticateMessage(username, ticket string) []byte {
	b := pbString(nil, 1, username)
	b = pbString(b, 2, ticket)
	return pbUint(b, 5, 1) // opus
}
