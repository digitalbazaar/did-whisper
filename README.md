# DID Whisper Client _(did-whisper)_

> A demo encrypted pastebin client using Veres One DID Documents

## Table of Contents

- [Security](#security)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [License](#license)

## Security

Please note that this is a demo / proof-of-concept only, and makes no security
guarantees.

Also, sent messages are anonymous (the recipient has no way of knowing who sent
the message).

## Install

Requires Node.js 8.6+.

```
git clone https://github.com/digitalbazaar/did-whisper.git
cd did-whisper
npm install
npm link
```

## Usage

The client is designed to work with a
[`did-whisper-server`](https://github.com/digitalbazaar/did-whisper-server)
instance running somewhere, either locally on your machine or on some server.

If you're offline or prefer not to use a server to store the encrypted messages
(so you can pass along just their URLs), you can encrypt and decrypt raw text
directly (using the `-n` flag to encrypt).

### Encrypting messages

To encrypt a message (and receive a link to where it's stored):

```bash
did-whisper encrypt <did> [message] [options]
```

The message can be included inline, or redirected from stdin. For example:

```bash
$ did-whisper encrypt did:v1:test:nym:2pfPix2tcwa7gNoMRxdcHbEyFGqaVBPNntCsDZexVeHX < message.txt
http://localhost:5000/whisper/HkVxJRL5M
```

would encrypt the contents of the file `message.txt`.

The `did-whisper` client automatically saves the encrypted message to a
`did-whisper-server` service (unless it cannot be reached, or the `-n` option
is passed in.

#### Encrypting Options

- `-e, --exp` - Expire message in this time period (valid options:
  `5m`, `1h`, `1d`, `1w`).
  Default: `1w`.
- `-s, --store` - URL of the
  [`did-whisper-server`](https://github.com/digitalbazaar/did-whisper-server)
  to save messages to.
  Default: `https://whisper.demo.veres.one`.
- `-n, --no-store` - Do not save the message, just output the encrypted text
  to stdout.
  Default: `false`.

### Decrypting messages

If you just have the message URL:

```bash
did-whisper decrypt <saved message url>
```

If you have the raw encrypted message and know the recipient DID (it must be a
locally stored DID, since the client uses the private key stored in the DID
Document):

```bash
did-whisper decrypt <did> [message]
```

The encrypted message can be included inline, or redirected from stdin.

## Contribute

See [the contribute file](https://github.com/digitalbazaar/bedrock/blob/master/CONTRIBUTING.md)!

PRs accepted.

Small note: If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

[New BSD License (3-clause)](LICENSE)
