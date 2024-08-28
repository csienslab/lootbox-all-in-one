#include "../verifier.h"
#include "../prover_slow.h"
#include "aggutil.h"

/**
 * EvalAggVdf evalutes the VDF by computing y <- g^{2^t} and 
 * uses H_G (ClHash) to hash challenge into class group element g
 * in group D (with discriminant D).
 * {y} <- Eval(x, t), proof is generated from AggreateVdfProofs.
 * @param D The discriminant of the class group.
 * @param challenge_int The challenge in integer form.
 * @param t The number of squaring of group operations.
 * @return y The final result.
 * @return a_iter The number of iterations to generate a valid g.
*/
std::tuple<form, int> EvalAggVdf(integer D, integer challenge_int, uint64_t t) {
    integer Lroot = root(-D, 4);
    PulmarkReducer reducer;
    form y;
    int a_iter;
    tie(y, a_iter) = H_G(challenge_int, D);

    for (int i = 0; i < t; i++) {
        nudupl_form(y, y, D, Lroot);
        reducer.reduce(y);
    }

    return tie(y, a_iter);
}

/**
 * AggreateVdfProofs generates aggregated VDF proof.
 * This technique can only be used on VDFs in the same group (same discriminant).
 * https://www.ndss-symposium.org/wp-content/uploads/2022-234-paper.pdf
 * Section VII.(A)(2)
 * {proof, b_iter} <- AggreateVdfProofs(xs, ys, t).
 * @param D The discriminant of the class group.
 * @param challenge_integers Contains all challenge_integers of VDFs.
 * @param ys Contains all the result of VDFs.
 * @param num_iterations The number of squaring of group operations.
 * @param a_iters Contains all the number of iterations to generate a valid g of each VDF.
 * @return proof Is the aggregated proof.
 * @return b_iter Is the number of iterations to generate Fiat-Shamir challenge.
*/
std::tuple<form, int> AggreateVdfProofs(integer D,
    std::vector<integer>& challenge_integers, 
    std::vector<form>& ys,
    uint64_t num_iterations, 
    std::vector<int> a_iters)
{
    int d_size = D.num_bits();
    integer Lroot = root(-D, 4);
    PulmarkReducer reducer;
    int proofs_num = challenge_integers.size();
    std::vector<form> gs(proofs_num);

    // g_i <- H_{Cl(d)}(x_{root,j})
    for (int i = 0; i < proofs_num; i++) {
        gs[i] = H_GFast(challenge_integers[i], D, a_iters[i]);
    }

    // s = bin(g_1)||...||bin(g_n)||bin(y_1)...||bin(y_n)
    std::vector<uint8_t> s;
    for (int i = 0; i < proofs_num; i++){
        std::vector<uint8_t> g_bytes = SerializeForm(gs[i], d_size);
        std::vector<uint8_t> y_bytes = SerializeForm(ys[i], d_size);
        s.insert(s.end(), g_bytes.begin(), g_bytes.end());
        s.insert(s.end(), y_bytes.begin(), y_bytes.end());
    }

    integer B;
    int b_iter;
    // l <- H_{prime}(s)
    // B is the l here.
    // B is the Fiat-Shamir non-interactive challenge.
    tie(B, b_iter) = HashPrimeWithIteration(s, 264, {263});
    form agg_g = form::identity(D);

    for (int i = 0; i < proofs_num; i++){
        std::vector<uint8_t> seed = int2bytes(i);
        seed.insert(seed.end(), s.begin(), s.end());
        std::vector<uint8_t> hash(picosha2::k_digest_size);  // output of sha256
        picosha2::hash256(seed.begin(), seed.end(), hash.begin(), hash.end());
        // 2**(k_digest_size) = 2**32
        // alpha_j <- int(H(bin(j)||s))
        integer alpha(hash);
        agg_g = agg_g * FastPowFormNucomp(gs[i], D, alpha, Lroot, reducer);
    }

    // g^{2^T/l} = g^{2^T/B}
    form proof = PowFormWithQuotient(agg_g, D, num_iterations, B, Lroot, reducer);
    return std::make_tuple(proof, b_iter);
}

/**
 * VerifyAggProof verifies the x, y, aggregated_proofs and returns a boolean.
 * This technique can only be used on VDFs in the same group (same discriminant).
 * https://www.ndss-symposium.org/wp-content/uploads/2022-234-paper.pdf
 * Section VII.(A)(3)
 * {True, False} <- Verify(x, y, proof, t)
 * @param D The discriminant of the class group.
 * @param challenge_integers Contains all challenge_integers of VDFs.
 * @param ys Contains all the result of VDFs.
 * @param aggregated_proof Is the aggregated VDF proof from AggreateVdfProofs.
 * @param num_iterations Is the number of squaring of group operations.
 * @param nthreads Is the number of threads used to verify in parallel.
 * @param a_iters Contains all the number of iterations to generate a valid g of each VDF.
 * @param b_iter Is the number of iterations to generate Fiat-Shamir challenge.
 * @return is_valid To indicate whether the proof is valid.
*/
bool VerifyAggProof(integer &D,
    std::vector<integer>& challenge_integers,
    std::vector<form>& ys,
    form aggregated_proof,
    uint64_t num_iterations,
    size_t nthreads,
    std::vector<int> a_iters,
    int b_iter) {

    PulmarkReducer reducer;
    int proofs_num = challenge_integers.size();
    int d_size = D.num_bits();
    integer Lroot = root(-D, 4);
    std::vector<uint8_t> s;

    // g_i <- H_{Cl(d)}(x_{root,j})
    std::vector<form> gs(proofs_num);
    std::vector<std::thread> threads(nthreads);
    for(int tt = 0;tt<nthreads;tt++)
    {
        threads[tt] = std::thread(std::bind(
        [&](const int bi, const int ei, const int tt)
        {
            for (int i = bi; i < ei; i++){
                gs[i] = H_GFast(challenge_integers[i], D, a_iters[i]);
            }
        },tt*proofs_num/nthreads,(tt+1)==nthreads?proofs_num:(tt+1)*proofs_num/nthreads,tt));
    }
    std::for_each(threads.begin(),threads.end(),[](std::thread& x){x.join();});

    // s = bin(g_1)||...||bin(g_n)||bin(y_1)...||bin(y_n)
    for (int i = 0; i < proofs_num; i++){
        std::vector<uint8_t> g_bytes = SerializeForm(gs[i], d_size);
        std::vector<uint8_t> y_bytes = SerializeForm(ys[i], d_size);
        s.insert(s.end(), g_bytes.begin(), g_bytes.end());
        s.insert(s.end(), y_bytes.begin(), y_bytes.end());
    }
    
    // l <- H_{prime}(s)
    // B is the l here.
    // B is the Fiat-Shamir non-interactive challenge.
    integer B = HashPrimeFast(s, 264, {263}, b_iter);
    
    form agg_x = form::identity(D);
    form agg_y = form::identity(D);
    std::vector<form> agg_gs(nthreads), agg_ys(nthreads);
    // std::mutex g_pages_mutex;
    for(int tt = 0;tt<nthreads;tt++)
    {
        threads[tt] = std::thread(std::bind(
        [&](const int bi, const int ei, const int tt)
        {
            // PulmarkReducer and hash cannot be used as a shared variable in threads
            PulmarkReducer reducer;
            std::vector<uint8_t> hash(picosha2::k_digest_size);  // output of sha256
            form agg_xx = form::identity(D);
            form agg_yy = form::identity(D);
            for(int i = bi;i<ei;i++)
            {
                std::vector<uint8_t> seed = int2bytes(i);
                seed.insert(seed.end(), s.begin(), s.end());
                picosha2::hash256(seed.begin(), seed.end(), hash.begin(), hash.end());
                integer alpha(hash);
                agg_xx = agg_xx * FastPowFormNucomp(gs[i], D, alpha, Lroot, reducer);
                agg_yy = agg_yy * FastPowFormNucomp(ys[i], D, alpha, Lroot, reducer);        
            }
            // std::lock_guard<std::mutex> guard(g_pages_mutex);
            // do not use push_back or index racing will happend
            agg_gs[tt] = agg_xx;
            agg_ys[tt] = agg_yy;
        },tt*proofs_num/nthreads,(tt+1)==nthreads?proofs_num:(tt+1)*proofs_num/nthreads,tt));
    }
    std::for_each(threads.begin(),threads.end(),[](std::thread& x){x.join();});

    for (int i=0; i < agg_gs.size(); i++) {
        agg_x = agg_x * agg_gs[i];
        agg_y = agg_y * agg_ys[i];
    }

    // r <- 2^{T} / l = 2^{T} / B
    integer r = FastPow(2, num_iterations, B);
    form f1 = FastPowFormNucomp(aggregated_proof, D, B, Lroot, reducer);
    form f2 = FastPowFormNucomp(agg_x, D, r, Lroot, reducer);
    if (f1 * f2 == agg_y)
    {
        return true;
    }
    else
    {
        return false;
    }
}
