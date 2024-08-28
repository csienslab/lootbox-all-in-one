from headstart.acc.merkle_tree import (
    MerkleHash,
    MerkleTreeAccumulator,
    SortedMerkleTreeAccumulator,
)
from headstart.acc.rsa_accumulator import RSAAccumulator, RSAPrimeAccumulator
from headstart.acc.bqf_accumulator import BQFAccumulator, ChiaBQFAccumulator
from headstart.abstract import AbstractVDF
from headstart.vdf.toy_vdf import ToyVDF
from headstart.vdf.chia_vdf import ChiaVDF
from hashlib import sha256
from enum import Enum
from threading import Thread
from subprocess import check_output
import sys, os, random

# This implements https://www.ndss-symposium.org/wp-content/uploads/2022-234-paper.pdf special case L=1


class Phase(Enum):
    CONTRIBUTION = 1
    EVALUATION = 2


class Parameters:
    # accumulator = RSAAccumulator.generate(1024)
    # accumulator = RSAPrimeAccumulator.generate(1024)
    # accumulator = BQFAccumulator.generate(1024)
    accumulator = ChiaBQFAccumulator.generate(1024)
    # accumulator = MerkleTreeAccumulator(MerkleHash(sha256))
    # accumulator = SortedMerkleTreeAccumulator(MerkleHash(sha256))
    T = 2**16
    bits = 256
    # vdf = ToyVDF(bits, T)
    vdf = ChiaVDF(bits, T)


class VDFComputation:
    def __init__(self, vdf: AbstractVDF, challenge: bytes):
        self.vdf = vdf
        self.challenge = challenge
        self.done = False
        self.thread = Thread(target=self.run)
        self.thread.start()

    def run(self):
        self.proof = self.vdf.eval_and_prove(self.challenge)
        self.done = True

    def get(self):
        if not self.done:
            self.thread.join()
        return self.proof


class Server:
    def __init__(self):
        self.data: list[bytes] = []
        self.phase = Phase.CONTRIBUTION

    def contribute(self, x: bytes):
        if self.phase != Phase.CONTRIBUTION:
            raise ValueError("not in contribution phase")
        self.data.append(x)
        return len(self.data) - 1  # index of x in the data

    def stop_contribution(self):
        if self.phase != Phase.CONTRIBUTION:
            raise ValueError("not in contribution phase")
        self.phase = Phase.EVALUATION
        self.acc = Parameters.accumulator.accumulate(self.data)
        self.vdf = VDFComputation(
            Parameters.vdf, Parameters.accumulator.get_bytes(self.get_accval())
        )

    def get_accval(self):
        if self.phase != Phase.EVALUATION:
            raise ValueError("not in evaluation phase")
        return Parameters.accumulator.get_accval(self.acc)

    def get_acc_proof(self, data_index: int):
        if self.phase != Phase.EVALUATION:
            raise ValueError("not in evaluation phase")
        return Parameters.accumulator.witgen(self.acc, self.data, data_index)

    def get_proof(self):
        if self.phase != Phase.EVALUATION:
            raise ValueError("not in evaluation phase")
        return self.vdf.get()

    def get_randomness(self):
        proof = self.get_proof()
        return sha256(Parameters.vdf.extract_y(proof)).digest()


class Client:
    def __init__(self):
        self.id = os.urandom(4).hex()
        self.randomness = os.urandom(Parameters.bits // 8)

    def add_random_to(self, server: Server):
        self.index = server.contribute(self.randomness)

    def verify(self, server: Server):
        accval = server.get_accval()
        proof = server.get_acc_proof(self.index)
        if not Parameters.accumulator.verify(accval, proof, self.randomness):
            return False
        proof = server.get_proof()
        if not Parameters.vdf.verify(Parameters.accumulator.get_bytes(accval), proof):
            return False
        randomness = sha256(Parameters.vdf.extract_y(proof)).digest()
        if randomness != server.get_randomness():
            return False
        return True


class MaliciousServer1(Server):
    def stop_contribution(self):
        self.data[random.choice(range(len(self.data)))] = os.urandom(
            Parameters.bits // 8
        )
        return super().stop_contribution()


class MaliciousServer2(Server):
    def get_randomness(self):
        return os.urandom(Parameters.bits // 8)


def protocol_test(server_cls, n_clients):
    print("=" * 40)
    print(f"Testing protocol for {server_cls.__name__} with {n_clients} clients")
    server = server_cls()
    clients = [Client() for _ in range(n_clients)]
    for c in clients:
        c.add_random_to(server)
    server.stop_contribution()
    print("Randomness published by server:", server.get_randomness())
    for i, c in enumerate(clients):
        if not c.verify(server):
            print(f"Client {i} failed verification")
            break
    else:
        print("All clients successfully verified the randomness is correct")
    print()


if __name__ == "__main__":
    protocol_test(Server, 10)
    protocol_test(MaliciousServer1, 10)
    protocol_test(MaliciousServer2, 10)
