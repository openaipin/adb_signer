# ADB Signing Server

A Cloudflare Worker implementation of a remote ADB signing server, to be used with clients such as [adb_remote_auth](https://github.com/openaipin/adb_remote_auth). This was designed for the Humane Ai Pin, so the ADB cert did not have to be publicly distributed.

The openPin service for the Humane Ai Pin can be accessed at https://adb.openpinsigning.workers.dev/.

## Usage

Make an HTTP POST request to your worker with the entire body of your request consisting of the bytes you wish to sign. It should be 20 bytes long. The worker will return the token signed and base64 encoded, along with the Android public key as a normal string, but with base64 contents in normal PEM format.

Response:
```json
{
  "token": "some token base64 encoded",
  "public_key": "the Android generated public key"
}
```

## Deployment

Can be trivially deployed with `npx wrangler deploy`. You just specify the following secrets:

```
# Key in full PEM format (containing the starting and ending "-----BEGIN PRIVATE KEY-----" and all newlines)
PRIVATE_KEY=""
# Redirect URL if the worker receives a normal GET request
REDIRECT_URL="https://example.com"
```

## FAQ

### Why Rust

I intended to write this in Cloudflare Workers' native Node, but I couldn't get the signing to work correctly. I gave up and used a known good implementation.
