from chiavdf import (
    create_discriminant,
    prove,
    verify_wesolowski,
    aggvdf_eval,
    aggvdf_prove,
    aggvdf_verify,
)
from dataclasses import dataclass
from headstart.abstract import AbstractVDF, AggregateVDF
import msgpack
from headstart.vdf.toy_vdf import H_D


@dataclass
class ChiaEvalAndProof:
    discriminant_str: str
    result_y: bytes
    proof: bytes


class ChiaVDF(AbstractVDF):
    def __init__(self, bits: int, T: int):
        self.bits = bits
        self.T = T
        self.form_size = 100
        self.g = initial_el = b"\x08" + (b"\x00" * 99)

    def eval_and_prove(self, challenge: bytes) -> ChiaEvalAndProof:
        discriminant_str = create_discriminant(challenge, self.bits)
        blob = prove(challenge, self.g, self.bits, self.T)
        result_y = blob[: self.form_size]
        proof = blob[self.form_size :]
        return ChiaEvalAndProof(discriminant_str, result_y, proof)

    def verify(self, challenge: bytes, proof: ChiaEvalAndProof) -> bool:
        same_disc = create_discriminant(challenge, self.bits) == proof.discriminant_str
        return same_disc and verify_wesolowski(
            proof.discriminant_str,
            self.g,
            proof.result_y,
            proof.proof,
            self.T,
        )

    def extract_y(self, proof: ChiaEvalAndProof) -> bytes:
        return proof.result_y


class SerializableChiaVDF(AbstractVDF):
    def __init__(self, bits: int, T: int):
        self.vdf = ChiaVDF(bits, T)

    def eval_and_prove(self, challenge: bytes) -> bytes:
        proof = self.vdf.eval_and_prove(challenge)
        return msgpack.packb((proof.discriminant_str, proof.result_y, proof.proof))

    def verify(self, challenge: bytes, proof: bytes) -> bool:
        d, y, pi = msgpack.unpackb(proof)
        return self.vdf.verify(challenge, ChiaEvalAndProof(d, y, pi))

    def extract_y(self, proof: bytes) -> bytes:
        d, y, pi = msgpack.unpackb(proof)
        return y


def int2bytes(x):
    return int(x).to_bytes((x.bit_length() + 7) // 8, "big")


def bytes2int(x):
    return int.from_bytes(x, "big")


class AggregateChiaVDF(AggregateVDF):
    AGGREGATION_DISCRIMINANT_SEED = b"totally non-backdoored seed"  # should be constant

    def __init__(self, bits: int, T: int):
        self.bits = bits
        self.T = T
        self.d = H_D(self.AGGREGATION_DISCRIMINANT_SEED, 256)

    def eval(self, challenges: list[bytes]) -> list[bytes]:
        return aggvdf_eval(int2bytes(-self.d), self.T, challenges)

    def aggregate(self, challenges: list[bytes], ys: list[bytes]) -> bytes:
        return aggvdf_prove(int2bytes(-self.d), self.T, challenges, ys)

    def verify(self, challenges: list[bytes], ys: list[bytes], proof: bytes) -> bool:
        return aggvdf_verify(int2bytes(-self.d), self.T, challenges, ys, proof)


if __name__ == "__main__":
    for cls in [ChiaVDF, SerializableChiaVDF]:
        vdf = cls(256, 1 << 10)
        challenge = b"peko"
        proof = vdf.eval_and_prove(challenge)
        print(proof)
        print(vdf.verify(challenge, proof))
        print(vdf.extract_y(proof))

    avdf = AggregateChiaVDF(1024, 1 << 16)
    challenges = [b"peko", b"peko2", b"peko3"]
    ys = avdf.eval(challenges)
    pi = avdf.aggregate(challenges, ys)
    assert avdf.verify(challenges, ys, pi)
    challenges_extra = [b"peko4", b"peko5"]
    ys_extra = avdf.eval(challenges_extra)
    pi_all = avdf.aggregate(challenges + challenges_extra, ys + ys_extra)
    assert avdf.verify(challenges + challenges_extra, ys + ys_extra, pi_all)
