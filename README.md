# Bitcoin Peer Connector

This Python script fetches IP addresses from a Bitcoin DNS seed, establishes a handshake with each peer, sends a `getblocks` message, and then prints out the received block hashes from the `inv` response.

## Prerequisites

- Python 3.x

## Usage

```bash
python3 connector.py
