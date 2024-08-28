# import os

# e = os.urandom(32)


# def contribute(r: bytes):
#     pass


# def eval(contribution):
#     return e


from headstart.client import HeadStartClient
from hashlib import sha256
import os

headstart_server = os.environ.get("HEADSTART_SERVER", "http://localhost:5000")

client = HeadStartClient.from_server_url(headstart_server)


def contribute(r: bytes):
    return client.contribute(r)


def eval(contribution):
    return sha256(client.get_verified_randomness(contribution, contribution.stage + 5)).digest()
