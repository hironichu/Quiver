# Certificates Setup (`quiver/certs`)

This folder is for local certificate artifacts used by demos/tests and for documenting trust setup.

## What to trust globally on Linux

Add **CA certificates** (root and optionally intermediate), not leaf/server certificates.

- ✅ Add: CA cert(s) with `Basic Constraints: CA:TRUE`
- ❌ Do not add: server leaf cert (`CN=localhost` etc.) as a trust anchor

---

## Linux: add custom CA to system trust store

### Debian / Ubuntu

1. Copy CA certificate (`.crt`, PEM) to local trust path:
   - `sudo cp ./certs/<your-ca>.crt /usr/local/share/ca-certificates/<your-ca>.crt`
2. Rebuild trust store:
   - `sudo update-ca-certificates`

### RHEL / CentOS / Fedora

1. Copy CA certificate:
   - `sudo cp ./certs/<your-ca>.crt /etc/pki/ca-trust/source/anchors/`
2. Rebuild trust store:
   - `sudo update-ca-trust extract`

### Arch Linux

1. Copy CA certificate:
   - `sudo cp ./certs/<your-ca>.crt /etc/ca-certificates/trust-source/anchors/`
2. Rebuild trust store:
   - `sudo trust extract-compat`

### Alpine Linux

1. Copy CA certificate:
   - `sudo cp ./certs/<your-ca>.crt /usr/local/share/ca-certificates/`
2. Rebuild trust store:
   - `sudo update-ca-certificates`

---

## Verify CA is available to system trust

- Check distro trust bundle update output for your CA file name.
- Optional quick check (Debian-like bundle path):
  - `grep -n "BEGIN CERTIFICATE" /etc/ssl/certs/ca-certificates.crt | head`

---

## Verify in WebTransport demo

Run client with system trust:

- `swift run WebTransportDemo client --use-system-certificates -l debug`

To print loaded root CNs:

- `swift run WebTransportDemo client --use-system-certificates --dump-system-root-cns -l debug`

Expected:
- Trust source log with root count
- CN list containing your custom CA CN

---

## Notes

- If your server cert chains via an intermediate CA, ensure chain correctness on server side.
- If verification still fails, validate:
  - server cert SAN includes target host/IP
  - certificate dates are valid
  - key usage / extended key usage are appropriate for TLS server auth