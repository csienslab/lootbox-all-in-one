extern crate bincode;
use std::env;

#[macro_export]
/// Print a Matrix
macro_rules! slt_test {
    ($matrix:expr, $num_of_pub_inputs_plus_one:expr) => {
        for (row_index, row) in $matrix.iter().enumerate() {
            for (_, col_index) in row {
                assert!(row_index >= $num_of_pub_inputs_plus_one);
                assert!(row_index > *col_index);
            }
        }
    };
}

#[macro_export]
/// Print a Matrix
macro_rules! diag_test {
    ($matrix:expr) => {
        for (row_index, row) in $matrix.iter().enumerate() {
            for (_, col_index) in row {
                assert_eq!(row_index, *col_index);
            }
        }
    };
}

use std::fs::File;
use std::io::Write;
use ark_serialize::CanonicalSerialize;
use ac_compiler::constraint_builder::ConstraintBuilder;
use ac_compiler::error::Error;
use ac_compiler::gate::GateType;
use ac_compiler::variable::VariableType;
use ac_compiler::{circuit::Circuit, variable::Variable};
use ark_bn254::{Bn254, Fr};
use ark_ff::bytes::ToBytes;
use ark_ff::PrimeField;
use ark_ff::{to_bytes, Field, One, Zero};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_poly_commit::LabeledCommitment;
use ark_std::test_rng;
use blake2::Blake2s;
use fiat_shamir_rng::{FiatShamirRng, SimpleHashFiatShamirRng};
use homomorphic_poly_commit::marlin_kzg::KZG10;
use index_private_marlin::Marlin;
use proof_of_function_relation::t_functional_triple::TFT;
use rand_chacha::ChaChaRng;
use ac_compiler::circuit_compiler::{CircuitCompiler, VanillaCompiler};

type FS = SimpleHashFiatShamirRng<Blake2s, ChaChaRng>;
type F = Fr;
type PC = KZG10<Bn254>;
type MarlinInst = Marlin<Fr, PC, FS>;

pub fn enforce_xor<F: Field>(
    cb: &mut ConstraintBuilder<F>,
    a: &Variable<F>,
    c: &Variable<F>,
    minus_one: &Variable<F>,
) -> Result<Variable<F>, Error> {
    let neg_a = cb.enforce_constraint(&a, &minus_one, GateType::Mul, VariableType::Witness)?;
    let b = cb.enforce_constraint(&c, &neg_a, GateType::Add, VariableType::Witness)?;
    let bc = cb.enforce_constraint(&b, &c, GateType::Mul, VariableType::Witness)?;
    let ac = cb.enforce_constraint(&a, &c, GateType::Mul, VariableType::Witness)?;
    let neg_ac =
        cb.enforce_constraint(&ac, &minus_one, GateType::Mul, VariableType::Witness)?;
    let bcac = cb.enforce_constraint(&bc, &neg_ac, GateType::Add, VariableType::Witness)?;
    cb.enforce_constraint(&bcac, &a, GateType::Add, VariableType::Witness)
}

pub fn build_xor_circuit<F: Field>(
    cb: &mut ConstraintBuilder<F>,
    a_val: Vec<F>,
    b_val: Vec<F>,
) -> Result<(), Error> {
    let mut a = Vec::new();
    let mut b = Vec::new();

    for i in 0 .. a_val.len() {
        a.push( cb.new_input_variable(&format!("a{idx}", idx=i), a_val[i])?  );
        b.push( cb.new_input_variable(&format!("b{idx}", idx=i), b_val[i])?  );
    }
    let minus_one = cb.new_input_variable("minus_one", F::zero() - F::one())?;
    let one = cb.new_input_variable("one", F::one())?;
    
    let mut out = enforce_xor(cb, &a[0], &b[0], &minus_one)?;
    for i in 1 .. a_val.len() {
        let xor_out = enforce_xor(cb, &a[i], &b[i], &minus_one)?;
        out = cb.enforce_constraint(&out, &xor_out, GateType::Mul, VariableType::Witness)?;
    }

    // let _out = enforce_xor(cb, &a[3], &b[3], &minus_one)?;
    let _ = cb.enforce_constraint(&out, &one, GateType::Mul, VariableType::Output)?;

    Ok(())
}

fn commit_function<Func>(constraints: Func, vk_bin_filename: &String, tft_bin_filename: &String)
where
    Func: FnOnce(&mut ConstraintBuilder<F>) -> Result<(), Error>,
{
    let mut cb = ConstraintBuilder::<F>::new();

    let synthesized_circuit = Circuit::synthesize(constraints, &mut cb).unwrap();
    let (index_info, a, b, c) = VanillaCompiler::<F>::ac2tft(&synthesized_circuit);
    let domain_k =
        GeneralEvaluationDomain::<F>::new(index_info.number_of_non_zero_entries).unwrap();
    let domain_h = GeneralEvaluationDomain::<F>::new(index_info.number_of_constraints).unwrap();
    let rng = &mut test_rng();
    let universal_srs = MarlinInst::universal_setup(&index_info, rng).unwrap();
    let (pk, vk) = MarlinInst::index(&universal_srs, &index_info, a, b, c, rng).unwrap();
    let labels = vec![
        "a_row", "a_col", "a_val", "b_row", "b_col", "b_val", "c_row", "c_col", "c_val",
    ];
    let commits: Vec<LabeledCommitment<_>> = vk
        .commits
        .iter()
        .zip(labels.iter())
        .map(|(cm, &label)| {
            LabeledCommitment::new(label.into(), cm.clone(), Some(domain_k.size() + 1))
        })
        .collect();

    let mut fs_rng = FS::initialize(&to_bytes!(b"Testing :)").unwrap());

    //JUST REVERSE ROW A AND COL A TO GET STRICTLY UPPER TRIANGULAR
    let tft_proof = TFT::<F, PC, FS>::prove(
        &pk.committer_key,
        index_info.number_of_input_rows,
        &domain_k,
        &domain_h,
        Some(domain_k.size() + 1), //enforced_degree_bound
        &pk.index.a_arith.col,     // row_a_poly,
        &pk.index.a_arith.row,     // col_a_poly,
        &commits[1],               // row_a_commit,
        &commits[0],               // col_a_commit,
        &pk.rands[1],              // row_a_random,
        &pk.rands[0],              // col_a_random,
        &pk.index.b_arith.col,     // row_b_poly,
        &pk.index.b_arith.row,     // col_b_poly,
        &commits[4],               // row_b_commit,
        &commits[3],               // col_b_commit,
        &pk.rands[4],              // row_b_random,
        &pk.rands[3],              // col_b_random,
        &pk.index.c_arith.row,     // row_c_poly,
        &pk.index.c_arith.col,     // col_c_poly,
        &pk.index.c_arith.val,     // val_c_poly,
        &commits[6],               // row_c_commit,
        &commits[7],               // col_c_commit,
        &commits[8],               // val_c_commit,
        &pk.rands[6],              // row_c_random,
        &pk.rands[7],              // col_c_random,
        &pk.rands[8],              // val_c_random,
        &mut fs_rng,               // fs_rng,
        rng,                       // rng,
    ).unwrap();
    
    let mut serialized_vk = vec![];
    vk.serialize(&mut serialized_vk).unwrap();
    
    File::create(vk_bin_filename)
    .expect("Failed to create file")
    .write_all(&serialized_vk).expect("Failed to write to file");
    
    File::create(tft_bin_filename)
            .expect("Failed to create file")
            .write_all(&tft_proof).expect("Failed to write to file");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    let vk_bin_filename = &args[1];
    let tft_bin_filename = &args[2];
    
    let a_val = vec![ F::from(0), F::from(0), F::from(0)];
    let b_val = vec![ F::from(0), F::from(0), F::from(0)];
    let expected_output = F::from(1);
    
    let mut inputs = vec![ F::one() ];
    for i in 0 .. a_val.len() {
        inputs.push( a_val[i] );
        inputs.push( b_val[i] );
    }
    inputs.push( F::from(-1) );
    inputs.push( F::from(1) );

    let constraints = |cb: &mut ConstraintBuilder<F>| -> Result<(), Error> {
        build_xor_circuit::<Fr>(cb, a_val, b_val)?;
        Ok(())
    };
    
    let outputs = vec![expected_output];
    commit_function(constraints, vk_bin_filename, tft_bin_filename);
}
