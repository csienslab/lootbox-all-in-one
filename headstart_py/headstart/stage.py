from headstart.acc.merkle_tree import MerkleHash, MerkleTreeAccumulator
from headstart.abstract import AggregateVDF
from headstart.vdf.chia_vdf import SerializableChiaVDF, AggregateChiaVDF
from hashlib import sha256
from enum import Enum
from threading import Thread, Lock
import sys, os, random, time
from typing import Optional

# This implements https://www.ndss-symposium.org/wp-content/uploads/2022-234-paper.pdf special case L=1


class Phase(Enum):
    NONE = 0
    CONTRIBUTION = 1
    EVALUATION = 2
    DONE = 3

    def __lt__(self, other):
        return self.value < other.value

    def __ge__(self, other):
        return self.value >= other.value


class Parameters:
    accumulator = MerkleTreeAccumulator(MerkleHash(sha256))
    T = 2**10
    bits = 256
    # vdf = SerializableChiaVDF(bits, T)
    avdf = AggregateChiaVDF(bits, T)

    @staticmethod
    def hash(y: bytes):
        return sha256(y).digest()


class VDFComputation:
    def __init__(self, vdf: AggregateVDF, challenge: bytes):
        self.vdf = vdf
        self.challenge = challenge
        self.done = False
        self.thread = Thread(target=self.run)
        self.thread.start()

    def run(self, callback=None):
        self.y = self.vdf.eval([self.challenge])[0]
        self.done = True
        if callback:
            callback()

    def get(self):
        if not self.done:
            raise ValueError("not done yet")
        return self.y


class Stage:
    def __init__(self, prev_stages: list["Stage"] = []):
        self.data: list[bytes] = [b"DUMMY VALUE"]  # to prevent some errors
        self.phase = Phase.CONTRIBUTION
        self.prev_stages = prev_stages

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
        if len(self.prev_stages) == 0:
            prev_stage_y = b""
        else:
            prev = self.prev_stages[-1]
            while prev.phase < Phase.DONE:
                time.sleep(1)
            prev_stage_y = prev.get_final_y()
        self.vdf_challenge = Parameters.hash(self.get_acc_val() + prev_stage_y)
        self.vdf_thread = Thread(target=self.vdf_run)
        self.vdf_thread.start()

    def vdf_run(self):
        self.vdf_y = Parameters.avdf.eval([self.vdf_challenge])[0]
        prev_challenges = [stage.vdf_challenge for stage in self.prev_stages]
        prev_ys = [stage.vdf_y for stage in self.prev_stages]
        self.vdf_proof = Parameters.avdf.aggregate(
            prev_challenges + [self.vdf_challenge], prev_ys + [self.vdf_y]
        )
        self.phase = Phase.DONE

    def get_acc_val(self):
        if self.phase < Phase.EVALUATION:
            raise ValueError("not in evaluation phase")
        return Parameters.accumulator.get_accval(self.acc)

    def get_acc_proof(self, data_index: int):
        if self.phase < Phase.EVALUATION:
            raise ValueError("not in evaluation phase")
        return Parameters.accumulator.witgen(self.acc, self.data, data_index)

    def get_vdf_proof(self):
        if self.phase < Phase.DONE:
            raise ValueError("not in done phase")
        return self.vdf_proof

    def get_final_y(self):
        if self.phase < Phase.DONE:
            raise ValueError("not in done phase")
        return self.vdf_y
