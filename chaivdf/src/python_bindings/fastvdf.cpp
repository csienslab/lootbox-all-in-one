#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "../aggvdf/aggvdf.h"
#include "../alloc.hpp"
#include "../prover_slow.h"
#include "../verifier.h"

namespace py = pybind11;

PYBIND11_MODULE(chiavdf, m) {
	m.doc() = "Chia proof of time";

	// Creates discriminant.
	m.def("create_discriminant",
	      [](const py::bytes &challenge_hash, int discriminant_size_bits) {
		      std::string challenge_hash_str(challenge_hash);
		      py::gil_scoped_release release;
		      auto challenge_hash_bits = std::vector<uint8_t>(
		          challenge_hash_str.begin(), challenge_hash_str.end());
		      integer D = CreateDiscriminant(challenge_hash_bits,
		                                     discriminant_size_bits);
		      return D.to_string();
	      });

	// Checks a simple wesolowski proof.
	m.def("verify_wesolowski", [](const string &discriminant, const string &x_s,
	                              const string &y_s, const string &proof_s,
	                              uint64_t num_iterations) {
		py::gil_scoped_release release;
		integer D(discriminant);
		form x = DeserializeForm(D, (const uint8_t *)x_s.data(), x_s.size());
		form y = DeserializeForm(D, (const uint8_t *)y_s.data(), y_s.size());
		form proof =
		    DeserializeForm(D, (const uint8_t *)proof_s.data(), proof_s.size());

		bool is_valid = false;
		VerifyWesolowskiProof(D, x, y, proof, num_iterations, is_valid);
		return is_valid;
	});

	// Checks an N wesolowski proof.
	m.def("verify_n_wesolowski",
	      [](const string &discriminant, const string &x_s,
	         const string &proof_blob, const uint64_t num_iterations,
	         const uint64_t disc_size_bits, const uint64_t recursion) {
		      py::gil_scoped_release release;
		      std::string proof_blob_str(proof_blob);
		      uint8_t *proof_blob_ptr =
		          reinterpret_cast<uint8_t *>(proof_blob_str.data());
		      int proof_blob_size = proof_blob.size();

		      return CheckProofOfTimeNWesolowski(
		          integer(discriminant), (const uint8_t *)x_s.data(),
		          proof_blob_ptr, proof_blob_size, num_iterations,
		          disc_size_bits, recursion);
	      });

	m.def("prove", [](const py::bytes &challenge_hash, const string &x_s,
	                  int discriminant_size_bits, uint64_t num_iterations) {
		std::string challenge_hash_str(challenge_hash);
		std::vector<uint8_t> result;
		{
			py::gil_scoped_release release;
			std::vector<uint8_t> challenge_hash_bytes(
			    challenge_hash_str.begin(), challenge_hash_str.end());
			integer D = CreateDiscriminant(challenge_hash_bytes,
			                               discriminant_size_bits);
			form x =
			    DeserializeForm(D, (const uint8_t *)x_s.data(), x_s.size());
			result = ProveSlow(D, x, num_iterations);
		}
		py::bytes ret =
		    py::bytes(reinterpret_cast<char *>(result.data()), result.size());
		return ret;
	});

	// Checks an N wesolowski proof, given y is given by 'GetB()' instead of a form.
	m.def("verify_n_wesolowski_with_b",
	      [](const string &discriminant, const string &B, const string &x_s,
	         const string &proof_blob, const uint64_t num_iterations,
	         const uint64_t recursion) {
		      std::pair<bool, std::vector<uint8_t>> result;
		      {
			      py::gil_scoped_release release;
			      std::string proof_blob_str(proof_blob);
			      uint8_t *proof_blob_ptr =
			          reinterpret_cast<uint8_t *>(proof_blob_str.data());
			      int proof_blob_size = proof_blob.size();
			      result = CheckProofOfTimeNWesolowskiWithB(
			          integer(discriminant), integer(B),
			          (const uint8_t *)x_s.data(), proof_blob_ptr,
			          proof_blob_size, num_iterations, recursion);
		      }
		      py::bytes res_bytes =
		          py::bytes(reinterpret_cast<char *>(result.second.data()),
		                    result.second.size());
		      py::tuple res_tuple = py::make_tuple(result.first, res_bytes);
		      return res_tuple;
	      });

	m.def("get_b_from_n_wesolowski",
	      [](const string &discriminant, const string &x_s,
	         const string &proof_blob, const uint64_t num_iterations,
	         const uint64_t recursion) {
		      py::gil_scoped_release release;
		      std::string proof_blob_str(proof_blob);
		      uint8_t *proof_blob_ptr =
		          reinterpret_cast<uint8_t *>(proof_blob_str.data());
		      int proof_blob_size = proof_blob.size();
		      integer B = GetBFromProof(
		          integer(discriminant), (const uint8_t *)x_s.data(),
		          proof_blob_ptr, proof_blob_size, num_iterations, recursion);
		      return B.to_string();
	      });

	m.def("exp", [](const string &a_be, const string &b_be, const string &c_be,
	                const py::list &exp_be_list) {
		// a_be, b_be, c_be, exp_be are big endian bytes
		// exp_be_list is a list of big endian bytes
		// returns a tuple of big endian bytes
		string str_a, str_b, str_c;
		{
			py::gil_scoped_release release;
			integer a, b, c;
			mpz_import(a.impl, a_be.size(), 1, 1, 1, 0, a_be.data());
			mpz_import(b.impl, b_be.size(), 1, 1, 1, 0, b_be.data());
			mpz_import(c.impl, c_be.size(), 1, 1, 1, 0, c_be.data());
			integer D = b * b - integer(4) * a * c;
			integer L = root(-D, 4);
			form x = form::from_abc(a, b, c);
			PulmarkReducer reducer;

			auto exps = exp_be_list.cast<std::vector<string>>();
			for (auto &exp_be : exps) {
				integer exp;
				mpz_import(exp.impl, exp_be.size(), 1, 1, 1, 0, exp_be.data());
				x = FastPowFormNucomp(x, D, exp, L, reducer);
			}
			auto res_a = x.a.to_bytes();
			auto res_b = x.b.to_bytes();
			auto res_c = x.c.to_bytes();
			str_a = string(res_a.begin(), res_a.end());
			str_b = string(res_b.begin(), res_b.end());
			str_c = string(res_c.begin(), res_c.end());
		}
		return py::make_tuple(py::bytes(str_a), py::bytes(str_b),
		                      py::bytes(str_c));
	});

	m.def("aggvdf_eval", [](const string &d_be, const uint64_t num_iterations,
	                        const py::list &challenges_be_list) {
		{
			py::gil_scoped_release release;
			integer D;
			mpz_import(D.impl, d_be.size(), 1, 1, 1, 0, d_be.data());
			D = -D;
			int d_bits = D.num_bits();

			auto challenges = challenges_be_list.cast<std::vector<string>>();
			std::vector<form> ys(challenges.size());
			std::vector<py::bytes> results(challenges.size());
			for (int i = 0; i < challenges.size(); i++) {
				auto &challenge_be = challenges[i];
				integer challenge;
				mpz_import(challenge.impl, challenge_be.size(), 1, 1, 1, 0,
				           challenge_be.data());
				form y;
				int iters;
				std::tie(y, iters) = EvalAggVdf(D, challenge, num_iterations);
				auto serialized = SerializeForm(y, d_bits);
				serialized.push_back(iters & 0xff);
				serialized.push_back((iters >> 8) & 0xff);
				serialized.push_back((iters >> 16) & 0xff);
				serialized.push_back((iters >> 24) & 0xff);
				{
					py::gil_scoped_acquire acquire;
					results[i] =
					    py::bytes(reinterpret_cast<char *>(serialized.data()),
					              serialized.size());
				}
			}
			return results;
		}
	});

	m.def("aggvdf_prove", [](const string &d_be, const uint64_t num_iterations,
	                         const py::list &challenges_be_list,
	                         const py::list &ys_serialized_list) {
		{
			py::gil_scoped_release release;
			integer D;
			mpz_import(D.impl, d_be.size(), 1, 1, 1, 0, d_be.data());
			D = -D;
			int d_bits = D.num_bits();

			auto challenges = challenges_be_list.cast<std::vector<string>>();
			auto ys_serialized = ys_serialized_list.cast<std::vector<string>>();
			std::vector<integer> challenge_integers(challenges.size());
			std::vector<form> ys(ys_serialized.size());
			std::vector<int> a_iters(ys_serialized.size());
			for (int i = 0; i < ys_serialized.size(); i++) {
				auto &y_serialized = ys_serialized[i];
				auto &challenge_be = challenges[i];
				mpz_import(challenge_integers[i].impl, challenge_be.size(), 1,
				           1, 1, 0, challenge_be.data());
				// extract a_iters from serialized y
				int a_iters_offset = y_serialized.size() - 4;
				a_iters[i] = (y_serialized[a_iters_offset] & 0xff) |
				             ((y_serialized[a_iters_offset + 1] & 0xff) << 8) |
				             ((y_serialized[a_iters_offset + 2] & 0xff) << 16) |
				             ((y_serialized[a_iters_offset + 3] & 0xff) << 24);
				y_serialized.resize(a_iters_offset);
				// deserialize y
				ys[i] = DeserializeForm(D, (const uint8_t *)y_serialized.data(),
				                        y_serialized.size());
			}
			form aggregated_proof;
			int b_iter;
			tie(aggregated_proof, b_iter) = AggreateVdfProofs(
			    D, challenge_integers, ys, num_iterations, a_iters);
			auto serialized = SerializeForm(aggregated_proof, d_bits);
			serialized.push_back(b_iter & 0xff);
			serialized.push_back((b_iter >> 8) & 0xff);
			serialized.push_back((b_iter >> 16) & 0xff);
			serialized.push_back((b_iter >> 24) & 0xff);
			{
				py::gil_scoped_acquire acquire;
				return py::bytes(reinterpret_cast<char *>(serialized.data()),
				                 serialized.size());
			}
		}
	});

	m.def("aggvdf_verify", [](const string &d_be, const uint64_t num_iterations,
	                          const py::list &challenges_be_list,
	                          const py::list &ys_serialized_list,
	                          string &serilized_aggregated_proof) {
		{
			py::gil_scoped_release release;
			integer D;
			mpz_import(D.impl, d_be.size(), 1, 1, 1, 0, d_be.data());
			D = -D;
			int d_bits = D.num_bits();

			auto challenges = challenges_be_list.cast<std::vector<string>>();
			auto ys_serialized = ys_serialized_list.cast<std::vector<string>>();
			std::vector<integer> challenge_integers(challenges.size());
			std::vector<form> ys(ys_serialized.size());
			std::vector<int> a_iters(ys_serialized.size());
			for (int i = 0; i < ys_serialized.size(); i++) {
				auto &y_serialized = ys_serialized[i];
				auto &challenge_be = challenges[i];
				mpz_import(challenge_integers[i].impl, challenge_be.size(), 1,
				           1, 1, 0, challenge_be.data());
				// extract a_iters from serialized y
				int a_iters_offset = y_serialized.size() - 4;
				a_iters[i] = (y_serialized[a_iters_offset] & 0xff) |
				             ((y_serialized[a_iters_offset + 1] & 0xff) << 8) |
				             ((y_serialized[a_iters_offset + 2] & 0xff) << 16) |
				             ((y_serialized[a_iters_offset + 3] & 0xff) << 24);
				y_serialized.resize(a_iters_offset);
				// deserialize y
				ys[i] = DeserializeForm(D, (const uint8_t *)y_serialized.data(),
				                        y_serialized.size());
			}
			form aggregated_proof;
			int b_iter;
			// extract b_iter from serialized aggregated proof
			int b_iter_offset = serilized_aggregated_proof.size() - 4;
			b_iter =
			    (serilized_aggregated_proof[b_iter_offset] & 0xff) |
			    ((serilized_aggregated_proof[b_iter_offset + 1] & 0xff) << 8) |
			    ((serilized_aggregated_proof[b_iter_offset + 2] & 0xff) << 16) |
			    ((serilized_aggregated_proof[b_iter_offset + 3] & 0xff) << 24);
			serilized_aggregated_proof.resize(b_iter_offset);
			// deserialize aggregated proof
			aggregated_proof = DeserializeForm(
			    D, (const uint8_t *)serilized_aggregated_proof.data(),
			    serilized_aggregated_proof.size());
			bool valid =
			    VerifyAggProof(D, challenge_integers, ys, aggregated_proof,
			                   num_iterations, 4, a_iters, b_iter);
			return valid;
		}
	});
}
