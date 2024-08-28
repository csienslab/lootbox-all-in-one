import hashlib
from KZG10 import *
import time
from py_ecc import fields
import math


# Global variables
F = GF(curve.curve_order)
PK = TrustedSetup.generate(F, 5, True)
intervals = 10
CommonPolynomial = [8, 7, 8, 6, 5, 3, 2, 1, 2, 3, 4, 5, 7]
BulletinBoardDir = "./BulletinBoard/"
CommitmentFileName = "commitment.txt"
EvalProofFileName = "evaluation_proofs.txt"

realProbability = 0.5


def isWinning(y: Field) -> bool:
    m = math.floor(1 / realProbability)
    if y.v % m == 0:
        return True
    return False


class LootBoxInput:
    def __init__(self, r, o):
        self.r = r
        self.o = o

    def getFieldInput(self):
        string_input = self.r + self.o
        hashed_value = hashlib.sha256(string_input.encode()).hexdigest()
        return F(int(hashed_value, 16))


class FunctionalCommitment:
    def __init__(self, degree=3, randomCoeff=False, coeff=None) -> None:
        self.degree = degree
        if randomCoeff:
            self.coeff = [F.random() for _ in range(degree)]
        else:
            self.coeff = [F(CommonPolynomial[i]) for i in range(degree)]
        if coeff:
            self.coeff = [F(c) for c in coeff]
            if len(coeff) != degree + 1:
                raise ValueError("Invalid number of coefficients")
        self.c = CommitSum(PK, self.coeff)

    def getCommitment(self):
        return self.c

    def evalAndProof(self, input: LootBoxInput):
        return self.evalAndProofRaw(input.getFieldInput())

    def evalAndProofRaw(self, i: Field):
        y = polynomial(i, self.coeff)
        W = CommitDivision_optimized(PK, i, self.coeff)

        return y, W


def verifyEvalProof(c, input: LootBoxInput, y, W) -> bool:
    return verifyEvalProofRaw(c, input.getFieldInput(), y, W)


def verifyEvalProofRaw(c, i: Field, y, W) -> bool:
    g2_i = curve.multiply(curve.G2, int(i))
    g2_x_sub_i = curve.add(PK.g2_powers[1], curve.neg(g2_i))  # x-i
    g1_phi_at_i = curve.multiply(curve.G1, int(y))
    g1_phi_at_x_sub_i = curve.add(c, curve.neg(g1_phi_at_i))
    a = curve.pairing(g2_x_sub_i, W)
    b = curve.pairing(curve.G2, curve.neg(g1_phi_at_x_sub_i))
    ab = a * b
    return ab == curve.FQ12.one()


from subprocess import check_output
from os.path import join


class Rust_FunctionalCommitment:
    def __init__(self, BulletinBoardDir="") -> None:
        self.BulletinBoardDir = BulletinBoardDir
        self.c = [join(BulletinBoardDir, "vk.bin"), join(BulletinBoardDir, "tft.bin")]
        check_output(["./functional-commitment/commit_function", self.c[0], self.c[1]])

    def getCommitment(self):
        return self.c

    def evalAndProof(self, input: LootBoxInput, cnt: int):
        i = int(input.getFieldInput())

        a = str(i & 0b111)
        b = str((i & 0b111000) >> 3)
        W = join(BulletinBoardDir, f"proof{cnt}.bin")
        output = (
            check_output(["./functional-commitment/make_proof", W, a, b])
            .strip()
            .decode()
        )
        print(a, b, output)
        y = 1 if output == "Win!" else 0

        return y, W


def Rust_verifyEvalProof(c, input: LootBoxInput, y, W) -> bool:
    i = int(input.getFieldInput())

    a = str(i & 0b111)
    b = str((i & 0b111000) >> 3)

    output = (
        check_output(["./functional-commitment/verify", W, c[0], c[1], a, b, y])
        .strip()
        .decode()
    )
    print(output)

    return output == "Verify Success!"


if __name__ == "__main__":
    fc = FunctionalCommitment()
    c = fc.getCommitment()

    with open("BulletinBoard.txt", "w") as f:
        f.write(str(c[0]))
        f.write("###")
        f.write(str(c[1]))

    with open("BulletinBoard.txt", "r") as f:
        s = f.read().split("###")
        a = (curve.FQ(int(s[0])), curve.FQ(int(s[1])))
        print(a == c)


def serializeECC(p: Tuple):
    s = str(p[0])
    s += ","
    s += str(p[1])
    return ",".join([str(e) for e in p])


def deserializeEcc(s: str):
    return tuple([curve.FQ(int(e)) for e in s.split(",")])
