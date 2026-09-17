# Basic JWKS Server

This project implements a basic RESTful JWKS server using Python and Flask.

## Features

- Generates RSA key pairs
- Assigns a unique Key ID (`kid`) to each key
- Associates an expiration time with each key
- Provides a JWKS endpoint containing only valid public keys
- Provides a mock authentication endpoint
- Creates RS256 signed JWTs
- Supports expired JWT generation using the `expired` query parameter
- Includes automated tests

## Endpoints

### GET /.well-known/jwks.json

Returns currently valid public RSA keys in JWKS format.

Example:

```bash
curl http://localhost:8080/.well-known/jwks.json