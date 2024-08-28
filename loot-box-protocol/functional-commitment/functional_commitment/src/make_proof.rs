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
use ark_ff::{to_bytes, Field, One};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_poly_commit::LabeledCommitment;
use ark_std::test_rng;
use blake2::Blake2s;
use fiat_shamir_rng::{FiatShamirRng, SimpleHashFiatShamirRng};
use homomorphic_poly_commit::marlin_kzg::KZG10;
use index_private_marlin::Marlin;
use proof_of_function_relation::t_functional_triple::TFT;
use rand_chacha::ChaChaRng;

type FS = SimpleHashFiatShamirRng<Blake2s, ChaChaRng>;
use ac_compiler::circuit_compiler::{CircuitCompiler, VanillaCompiler};

// use crate::{diag_test, slt_test};

type F = Fr;
type PC = KZG10<Bn254>;

type MarlinInst = Marlin<Fr, PC, FS>;

fn circuit_test_template<Func>(constraints: Func, inputs: &Vec<F>, outputs: &Vec<F>, proof_bin_filename: &String)
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
    let proof = MarlinInst::prove(&pk, cb.assignment, rng).unwrap();
    let mut serialized_proof = vec![];
    proof.serialize(&mut serialized_proof).unwrap();
    File::create(proof_bin_filename)
    .expect("Failed to create file")
    .write_all(&serialized_proof).expect("Failed to write to file");
    
    // let pcs = MarlinInst::_proof(&vk, inputs, outputs, proof, rng, &pk.committer_key).unwrap();
    // for i in 0 .. pcs.len() {
    //     let mut serialized_pc = vec![];
    //     let pc = &pcs[i];
    //     println!("{}", pc.label());
    //     pc.commitment().serialize(&mut serialized_pc).unwrap();
    //     File::create( pc.label().to_owned() + ".bin" )
    //     .expect("Failed to create file")
    //     .write_all(&serialized_proof).expect("Failed to write to file");
    // }

    assert!(MarlinInst::verify(&vk, inputs, outputs, proof, rng, &pk.committer_key).unwrap());
}

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

fn main() {
    let args: Vec<String> = env::args().collect();
    
    let proof_bin_filename = &args[1];
    let input_a: i32 = args[2].parse().unwrap();
    let input_b: i32 = args[3].parse().unwrap();
    
    // let a_val = vec![ F::from(1), F::from(0), F::from(1)];
    // let b_val = vec![ F::from(0), F::from(1), F::from(0)];
    let a_val :Vec<_> = (0..3).map (|n| F::from((input_a >> n) & 1)).collect();
    let b_val :Vec<_> = (0..3).map (|n| F::from((input_b >> n) & 1)).collect();
    let expected_output = if input_a ^ input_b == 7 { F::from(1) } else { F::from(0) };
    println!("{}", if input_a ^ input_b == 7 { "Win!" } else { "Lose." });

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
    circuit_test_template(constraints, &inputs, &outputs, proof_bin_filename);
}
