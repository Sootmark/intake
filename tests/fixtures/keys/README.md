# Test keys

Generated for these tests only (OpenSSL, 2048-bit RSA). They protect nothing: never reuse them.

- `frontend.key` (PKCS#1) and `frontend-pkcs8.key` (the same key, PKCS#8): the key the X509 fixtures are encrypted for.
- `ca.key`: an unrelated key, placed first in `server.config.yaml` so tests prove the right key is found among several.
- `server.config.yaml`: a synthetic Velociraptor server config holding both keys as YAML block scalars.
