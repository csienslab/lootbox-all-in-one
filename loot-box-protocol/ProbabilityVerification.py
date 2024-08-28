from common import *
import PRB
from MappingFunction import mappingFunction
import time
import csv
import os
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from argparse import ArgumentParser

rows = [[sampleSize] for sampleSize in range(30, 101, 5)]


class ProbabilityVerificationServer:
    def __init__(self) -> None:
        pass

    def setup(self, degree=3, randomCoeff=False):
        self.fc = FunctionalCommitment(degree, randomCoeff)
        c = self.fc.getCommitment()

        # write PK, c, M, n onto bulletin board
        with open(BulletinBoardDir + CommitmentFileName, "w") as f:
            f.write(serializeECC(c))
        self.contribution = PRB.contribute(os.urandom(32))

    def eval(self):
        seed = PRB.eval(self.contribution)
        testData = mappingFunction.mapToTestData(seed)

        # result = []
        # start = time.time()
        # i = 0
        # row = 0
        # for r, o in testData:
        #     i += 1
        #     input = LootBoxInput(r, o)
        #     y, W = self.fc.evalAndProof(input)
        #     if i >= 30 and i % 5 == 0:
        #         rows[row].append(time.time() - start)
        #         row += 1

        #     result.append((y, W))
        # print(W, type(W), type(W[0]))

        with ProcessPoolExecutor(max_workers=CPU_CORES) as executor:
            result = executor.map(
                self.fc.evalAndProof, [LootBoxInput(*d) for d in testData]
            )

        print(
            "Evaluation succeeded, write the evaluation and proofs on the bulletin board."
        )
        with open(BulletinBoardDir + EvalProofFileName, "w") as f:
            for y, W in result:
                f.write(str(y.v) + "#" + serializeECC(W))
                f.write("\n")


client_contribution = PRB.contribute(os.urandom(32))


def verifyProbability() -> bool:
    # get commitment c from bulletin board
    with open(BulletinBoardDir + CommitmentFileName, "r") as f:
        s = f.read()
        c = deserializeEcc(s)

    seed = PRB.eval(client_contribution)
    testData = mappingFunction.mapToTestData(seed)

    # get eval proofs from bulletin board
    evalProofs = []
    with open(BulletinBoardDir + EvalProofFileName, "r") as f:
        for line in f.readlines():
            a, b = line.strip().split("#")
            y = F(int(a))
            W = deserializeEcc(b)
            evalProofs.append((y, W))

    if len(testData) != len(evalProofs):
        print(
            f"Inconsistent amount: testData {len(testData)}, evalProofs {len(evalProofs)}"
        )
        return False

    # verify eval proofs
    # winningNumber = 0
    # row = 0
    # start = time.time()
    # for i in range(len(testData)):
    #     r, o = testData[i]
    #     input = LootBoxInput(r, o)
    #     y, W = evalProofs[i]
    #     if not verifyEvalProof(c, input, y, W):
    #         print(f"Verification failed on {i}th input, input: {input}, y: {y}, W: {W}")
    #         return False
    #     if isWinning(y):
    #         winningNumber += 1

    #     if i + 1 >= 30 and (i + 1) % 5 == 0:
    #         rows[row].append(time.time() - start)
    #         row += 1

    with ProcessPoolExecutor(max_workers=CPU_CORES) as executor:
        cs = [c] * len(testData)
        inputs = [LootBoxInput(*d) for d in testData]
        ys = [d[0] for d in evalProofs]
        ws = [d[1] for d in evalProofs]
        result = executor.map(verifyEvalProof, cs, inputs, ys, ws)

    for i, r in enumerate(result):
        if not r:
            print(f"Verification failed on {i}th input")
            return False
    winningNumber = sum([1 for y in ys if isWinning(y)])

    print(
        f"Verification done, amount: {len(testData)}, #winning: {winningNumber}, sample winning probability: {winningNumber / len(testData)}"
    )
    return True


class Rust_ProbabilityVerificationServer:
    def __init__(self) -> None:
        pass

    def setup(self):
        self.fc = Rust_FunctionalCommitment(BulletinBoardDir)
        c = self.fc.getCommitment()
        # write PK, c, M, n onto bulletin board
        with open(BulletinBoardDir + CommitmentFileName, "w") as f:
            f.write(c[0] + "#" + c[1])

        self.contribution = PRB.contribute(os.urandom(32))
        global client_contribution
        client_contribution = self.contribution

    def eval(self):
        seed = PRB.eval(self.contribution)
        testData = mappingFunction.mapToTestData(seed)

        # result = []
        # start = time.time()
        # i = 0
        # row = 0
        # for r, o in testData:
        #     i += 1
        #     input = LootBoxInput(r, o)
        #     y, W = self.fc.evalAndProof(input)
        #     if i >= 30 and i % 5 == 0:
        #         rows[row].append(time.time() - start)
        #         row += 1

        #     result.append((y, W))

        # since it is calling external program, thread works fine since GIL is released
        with ThreadPoolExecutor(max_workers=CPU_CORES) as executor:
            result = executor.map(
                self.fc.evalAndProof,
                [LootBoxInput(*d) for d in testData],
                range(len(testData)),
            )

        print(
            "Evaluation succeeded, write the evaluation and proofs on the bulletin board."
        )
        with open(BulletinBoardDir + EvalProofFileName, "w") as f:
            for y, W in result:
                f.write(str(y) + "#" + W)
                f.write("\n")


def Rust_verifyProbability() -> bool:
    # get commitment c from bulletin board
    with open(BulletinBoardDir + CommitmentFileName, "r") as f:
        s = f.read()
        c = s.strip().split("#")

    seed = PRB.eval(client_contribution)
    testData = mappingFunction.mapToTestData(seed)

    # get eval proofs from bulletin board
    evalProofs = []
    with open(BulletinBoardDir + EvalProofFileName, "r") as f:
        for line in f.readlines():
            a, b = line.strip().split("#")
            y = a
            W = b
            evalProofs.append((y, W))

    if len(testData) != len(evalProofs):
        print(
            f"Inconsistent amount: testData {len(testData)}, evalProofs {len(evalProofs)}"
        )
        return False

    # verify eval proofs
    # winningNumber = 0
    # row = 0
    # start = time.time()
    # for i in range(len(testData)):
    #     r, o = testData[i]
    #     input = LootBoxInput(r, o)
    #     y, W = evalProofs[i]
    #     if not Rust_verifyEvalProof(c, input, y, W):
    #         print(f"Verification failed on {i}th input, input: {input}, y: {y}, W: {W}")
    #         return False
    #     if y == "1":
    #         winningNumber += 1

    #     if i + 1 >= 30 and (i + 1) % 5 == 0:
    #         rows[row].append(time.time() - start)
    #         row += 1

    # since it is calling external program, thread works fine since GIL is released
    with ThreadPoolExecutor(max_workers=CPU_CORES) as executor:
        cs = [c] * len(testData)
        inputs = [LootBoxInput(*d) for d in testData]
        ys = [d[0] for d in evalProofs]
        ws = [d[1] for d in evalProofs]
        result = executor.map(Rust_verifyEvalProof, cs, inputs, ys, ws)

    for i, r in enumerate(result):
        if not r:
            print(f"Verification failed on {i}th input")
            return False
    winningNumber = sum([1 for y in ys if y == "1"])

    print(
        f"Verification done, amount: {len(testData)}, #winning: {winningNumber}, sample winning probability: {winningNumber / len(testData)}"
    )
    return True


def sampleRun():
    server = ProbabilityVerificationServer()
    server.setup()
    server.eval()
    verifyProbability()


def Rust_sampleRun():
    server = Rust_ProbabilityVerificationServer()
    server.setup()
    server.eval()
    Rust_verifyProbability()


class FakePRB:
    def __init__(self):
        self.r = os.urandom(32)

    def contribute(self, r):
        pass

    def eval(self, c):
        return self.r


def plotDifferentDegree(output, n_samples):
    global PRB
    PRB = FakePRB()
    server = ProbabilityVerificationServer()
    rows = [["degree", "setup", "evaluation", "verification"]]
    for degree in range(100, 201, 10):
        for _ in range(n_samples):
            t1 = time.time()
            server.setup(degree, True)
            t2 = time.time()
            server.eval()
            t3 = time.time()
            verifyProbability()
            t4 = time.time()

            rows.append([degree, t2 - t1, t3 - t2, t4 - t3])

    with open(output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(rows)


def plotDifferentSampleSize(output, n_samples):
    global PRB
    PRB = FakePRB()
    server = ProbabilityVerificationServer()
    rows = [["Sample Size", "setup", "evaluation", "verification"]]

    for sampleSize in range(30, 101, 10):
        for _ in range(n_samples):
            mappingFunction.setSampleSize(sampleSize)
            t1 = time.time()
            server.setup(150, True)
            t2 = time.time()
            server.eval()
            t3 = time.time()
            verifyProbability()
            t4 = time.time()

            rows.append([sampleSize, t2 - t1, t3 - t2, t4 - t3])

    with open(output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(rows)


def plotDifferentSampleSize_rust(output, n_samples):
    global PRB
    PRB = FakePRB()
    server = Rust_ProbabilityVerificationServer()
    rows = [["Sample Size", "setup", "evaluation", "verification"]]
    for sampleSize in range(30, 101, 10):
        for _ in range(n_samples):
            mappingFunction.setSampleSize(sampleSize)
            t1 = time.time()
            server.setup()
            t2 = time.time()
            server.eval()
            t3 = time.time()
            Rust_verifyProbability()
            t4 = time.time()

            rows.append([sampleSize, t2 - t1, t3 - t2, t4 - t3])

    with open(output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(rows)


if __name__ == "__main__":
    # server = ProbabilityVerificationServer()
    # server.setup(3, True)
    # server.eval()
    # verifyProbability()
    # print(rows)
    # sampleRun()
    # plotDifferentDegree()
    # plotDifferentSampleSize()

    parser = ArgumentParser()
    parser.add_argument(
        "type", choices=["polyc", "fc", "plot_deg", "plot_sample", "plot_sample_fc"]
    )
    parser.add_argument("--cpu", type=int, default=os.cpu_count() // 2)
    parser.add_argument("--output", default="output.csv")
    parser.add_argument("--n_samples", type=int, default=10)
    args = parser.parse_args()
    CPU_CORES = args.cpu
    if args.type == "polyc":
        sampleRun()
    elif args.type == "fc":
        Rust_sampleRun()
    elif args.type == "plot_deg":
        plotDifferentDegree(args.output, args.n_samples)
    elif args.type == "plot_sample":
        plotDifferentSampleSize(args.output, args.n_samples)
    elif args.type == "plot_sample_fc":
        plotDifferentSampleSize_rust(args.output, args.n_samples)
