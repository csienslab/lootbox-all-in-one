# Toy implementation of [HeadStart: Efficiently Verifiable and Low-Latency Participatory Randomness Generation at Scale](https://www.ndss-symposium.org/wp-content/uploads/2022-234-paper.pdf)

## Installation

```bash
python -m venv venv
. venv/bin/activate
pip install -r requirements.txt
```

> Special note of anonymized version of this repo: To install `chiavdf` listed in `requirements.txt`, it is necessary to use this [fork](https://anonymous.4open.science/r/chaivdf-3666/README.md) of chaivdf.

## Run Server

```bash
./run_server.sh  # default port 5000, edit run_server.sh to change
```

## Test client

```bash
python -m headstart.client
# see headstart/client.py for example usage
```
