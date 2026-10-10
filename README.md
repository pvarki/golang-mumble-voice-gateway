# voice-gateway

Lets browsers into Murmur (VOICE-PLAN §4.10, "b2"). Browsers cannot speak Mumble's TLS with a client
certificate, so the gateway speaks it for them over a WebSocket at `mtls.<domain>/ui/mumble/ws`.

1. Traefik verifies the browser's client certificate and forwards it in `X-Forwarded-Tls-Client-Cert`.
   The gateway accepts requests only from Traefik's Linkerd identity, and only from the rmui origin.
2. The browser's first message is a ticket from mumblermapi (`/ui/mumble/api/v1/voice/token`). The
   gateway checks that the ticket carries the same certificate as this connection.
3. The gateway logs in to Murmur with its own certificate, from a CA that signs nothing else, and with
   the ticket as the password. murmur-agent verifies the ticket and then checks the user's certificate
   from it exactly as it checks a phone's.
4. After that it forwards whole Mumble messages: everything from Murmur, and from the browser only
   voice, pings, moving itself between nets, permission queries and blob requests.

The gateway mints nothing and asserts no identity, holds no product credentials, cannot reach rmapi, and
runs no other processes. If compromised it exposes the sessions passing through it and lets tickets it
saw be replayed within their 60 seconds.

## Configuration

| Variable | Meaning |
|---|---|
| `GATEWAY_ORIGIN` | The only page origin allowed, `https://mtls.<domain>` (required) |
| `GATEWAY_MURMUR_NAME` | The name on Murmur's certificate, `tak.<domain>` (required) |
| `GATEWAY_MURMUR_ADDR` | Murmur's address, default `murmur.app-mumble.svc.cluster.local:64738` |
| `GATEWAY_MURMUR_CA` | CAs for Murmur's certificate, default `/trust/ca-cert.pem` |
| `GATEWAY_CERT`, `GATEWAY_KEY` | The gateway's client certificate, default `/certs/tls.{crt,key}`; read for every session, so a renewed one needs no restart |
| `GATEWAY_TRAEFIK_IDENTITY` | Traefik's Linkerd identity |
| `GATEWAY_LISTEN` | Default `:8080` |

## Development

```bash
task test:go
docker buildx build --load -t voice-gateway:dev voice-gateway
```
