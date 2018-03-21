# DID Whisper Client _(did-whisper)_

[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)

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
git checkout first-pass
npm install
npm link
```

## Usage

### Encrypting messages

```bash
did-whisper encrypt <did> [message]
```

The message can be included inline, or redirected from stdin. For example:

```bash
did-whisper encrypt did:v1:test:nym:2pfPix2tcwa7gNoMRxdcHbEyFGqaVBPNntCsDZexVeHX < message.txt > cipher.txt
```

Would encrypt the contents of the file `message.txt` and save them in the file
`cipher.txt`.

### Decrypting messages

Note: the recipient's DID must be a locally stored DID (the client uses
the private key stored in the DID Document).

```bash
did-whisper decrypt <did> [message]
```

The encrypted message can be included inline, or redirected from stdin.

## Contribute

See [the contribute file](https://github.com/digitalbazaar/bedrock/blob/master/CONTRIBUTING.md)!

PRs accepted.

Small note: If editing the Readme, please conform to the [standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

TBD
