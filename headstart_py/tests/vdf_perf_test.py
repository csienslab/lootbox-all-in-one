from headstart.vdf.chia_vdf import ChiaVDF
import timeit, os


def vdf_test(vdf: ChiaVDF):
    challenge = os.urandom(8)
    proof = vdf.eval_and_prove(challenge)
    assert vdf.verify(challenge, proof)
    y = vdf.extract_y(proof)


K = 3
for bits in [1024]:
    for T in range(16, 24):
        vdf = ChiaVDF(bits, 1 << T)
        t = timeit.timeit(lambda: vdf_test(vdf), number=K) / K
        print(f"bits={bits}, T={T}, time={t}")

"""
bits=1024, T=16, time=0.5948997130035423
bits=1024, T=17, time=1.1527132293170628
bits=1024, T=18, time=2.248782481998205
bits=1024, T=19, time=4.43606647234022
bits=1024, T=20, time=8.68817146832589
bits=1024, T=21, time=17.617124020995107
bits=1024, T=22, time=34.3421061343397
bits=1024, T=23, time=67.44681108933098
"""
