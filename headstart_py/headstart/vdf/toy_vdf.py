from headstart.math.bqf import BinaryQF, get_qf_principal_form, qf_pow, qf_frombytes, qf_tobytes
import gmpy2
from hashlib import sha256, shake_256
from typing import Generator
from dataclasses import dataclass
from headstart.abstract import AbstractVDF, AggregateVDF
from headstart.utils import H_kgen, H_P


def H_D(x: bytes, k: int) -> int:
    # hash `x` to a k-bit discriminant for imaginary quadratic fields
    for d in H_kgen(x, k):
        d |= 7
        if gmpy2.is_prime(d):
            return -d
    raise RuntimeError("unreachable")


def H_QF(x: bytes, d: int, k: int) -> BinaryQF:
    # hash `x` to a k-bit quadratic form for imaginary quadratic fields
    for a in H_kgen(x, k):
        a |= 3
        if gmpy2.is_prime(a):
            if pow(d, (a - 1) // 2, a) == 1:
                b = pow(d, (a + 1) // 4, a)
                if b % 2 != 1:
                    b = a - b
                c = (b * b - d) // (4 * a)
                return BinaryQF(a, b, c).reduced_form()
    raise RuntimeError("unreachable")


def compute_proof(g: BinaryQF, l: int, T: int) -> BinaryQF:
    # compute g^floor(2^T // l)
    # https://eprint.iacr.org/2018/623.pdf section 4.1 algorithm 4
    x = get_qf_principal_form(g.discriminant())
    r = 1
    for _ in range(T):
        b = 2 * r // l
        r = 2 * r % l
        x = (x * x * qf_pow(g, b)).reduced_form()
    return x


def vdf_eval(bits: int, g: BinaryQF, T: int):
    g = g.reduced_form()
    y = g
    for i in range(T):
        y = (y * y).reduced_form()
    return y.reduced_form()


def vdf_prove(bits: int, g: BinaryQF, T: int, y: BinaryQF):
    l = H_P(qf_tobytes(g, bits) + qf_tobytes(y, bits), bits)
    return compute_proof(g, l, T)


def vdf_eval_and_prove(bits: int, g: BinaryQF, T: int):
    y = vdf_eval(bits, g, T)
    pi = vdf_prove(bits, g, T, y)
    return y, pi


def vdf_verify(bits: int, g: BinaryQF, y: BinaryQF, pi: BinaryQF, T: int):
    g = g.reduced_form()
    y = y.reduced_form()
    l = H_P(qf_tobytes(g, bits) + qf_tobytes(y, bits), bits)
    r = pow(2, T, l)
    lhs = qf_pow(pi, l) * qf_pow(g, r)
    return lhs.reduced_form() == y


@dataclass
class ToyProof:
    d: int
    g: BinaryQF
    y: BinaryQF
    pi: BinaryQF


class ToyVDF(AbstractVDF):
    def __init__(self, bits: int, T: int):
        self.bits = bits
        self.T = T

    def eval_and_prove(self, challenge: bytes) -> ToyProof:
        d = H_D(challenge, self.bits)
        g = H_QF(challenge, d, self.bits)
        y, pi = vdf_eval_and_prove(self.bits, g, self.T)
        return ToyProof(d, g, y, pi)

    def verify(self, challenge: bytes, proof: ToyProof) -> bool:
        d = H_D(challenge, self.bits)
        g = H_QF(challenge, d, self.bits)
        return vdf_verify(self.bits, g, proof.y, proof.pi, self.T)

    def extract_y(self, proof: ToyProof) -> bytes:
        return qf_tobytes(proof.y, self.bits)


class AggregateToyVDF(AggregateVDF):
    AGGREGATION_DISCRIMINANT_SEED = b"totally non-backdoored seed"  # should be constant

    def __init__(self, bits: int, T: int):
        self.bits = bits
        self.T = T
        self.d = H_D(self.AGGREGATION_DISCRIMINANT_SEED, 256)

    def eval_one(self, challenge: bytes) -> BinaryQF:
        g = H_QF(challenge, self.d, self.bits)
        return vdf_eval(self.bits, g, self.T)

    def eval(self, challenges: list[bytes]) -> list[BinaryQF]:
        return [self.eval_one(challenge) for challenge in challenges]

    def compute_parameters(self, challenges: list[bytes], ys: list[BinaryQF]):
        gs = [H_QF(challenge, self.d, self.bits) for challenge in challenges]
        s = sha256(
            b"".join(qf_tobytes(g, self.bits) for g in gs)
            + b"".join(qf_tobytes(y, self.bits) for y in ys)
        ).digest()
        a = [
            next(H_kgen(str(j).encode() + s, self.bits))
            for j in range(1, len(challenges) + 1)
        ]
        l = H_P(s, self.bits)
        G = get_qf_principal_form(self.d)
        for a_j, g_j in zip(a, gs):
            G = (G * qf_pow(g_j, a_j)).reduced_form()
        return gs, a, l, G

    def aggregate(self, challenges: list[bytes], ys: list[BinaryQF]) -> BinaryQF:
        gs, a, l, G = self.compute_parameters(challenges, ys)
        pi = compute_proof(G, l, self.T)
        return pi

    def verify(self, challenges: list[bytes], ys: list[BinaryQF], pi: BinaryQF) -> bool:
        gs, a, l, G = self.compute_parameters(challenges, ys)
        Y = get_qf_principal_form(self.d)
        for a_j, y_j in zip(a, ys):
            Y = (Y * qf_pow(y_j, a_j)).reduced_form()
        r = pow(2, self.T, l)
        lhs = qf_pow(pi, l) * qf_pow(G, r)
        return lhs.reduced_form() == Y


if __name__ == "__main__":
    vdf = ToyVDF(256, 1 << 10)
    challenge = b"peko"
    proof = vdf.eval_and_prove(challenge)
    print(proof)
    print(vdf.verify(challenge, proof))

    avdf = AggregateToyVDF(256, 1 << 10)
    challenges = [b"peko", b"peko2", b"peko3"]
    ys = avdf.eval(challenges)
    pi = avdf.aggregate(challenges, ys)
    print(avdf.verify(challenges, ys, pi))

    # bits = int(sys.argv[1])
    # x = bytes.fromhex(sys.argv[2])
    # T = int(sys.argv[3])

    # d = H_D(x, bits)
    # g = H_QF(x, d, bits)
    # y, pi = vdf_eval(bits, g, T)
    # assert vdf_verify(bits, g, y, pi, T)
    # sys.stdout.buffer.write(qf_tobytes(y, bits))
    # sys.stdout.buffer.write(qf_tobytes(pi, bits))
