from headstart.vdf.chia_vdf import AggregateChiaVDF
import timeit, os


K = 3
for bits in [1024]:
    for T in range(16, 24):
        vdf = AggregateChiaVDF(bits, 1 << T)
        challenges = [os.urandom(8) for _ in range(10)]
        t_eval = timeit.timeit(lambda: vdf.eval(challenges[:1]), number=K) / K
        ys = vdf.eval(challenges)
        t_agg = timeit.timeit(lambda: vdf.aggregate(challenges, ys), number=K) / K
        print(f"bits={bits}, T={T}, t_eval={t_eval}, t_agg={t_agg}")

"""
bits=1024, T=16, t_eval=0.15650326833322956, t_agg=0.2770001553338564
bits=1024, T=17, t_eval=0.3043948106642347, t_agg=0.5275478893357407
bits=1024, T=18, t_eval=0.5998898110022614, t_agg=1.0272310823347652
bits=1024, T=19, t_eval=1.2044662256666925, t_agg=2.019543972996568
bits=1024, T=20, t_eval=2.4202779823341793, t_agg=4.1424726356684305
bits=1024, T=21, t_eval=4.797180801663974, t_agg=8.400596247331123
"""
