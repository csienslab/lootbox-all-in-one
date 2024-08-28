extern crate bincode;
use std::io::{self, Read};
use std::env;
#[macro_use]
extern crate ark_std;

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
use ark_poly_commit::{LabeledCommitment};
use ark_poly_commit::data_structures::PCCommitment;
use ark_std::test_rng;
use blake2::Blake2s;
use fiat_shamir_rng::{FiatShamirRng, SimpleHashFiatShamirRng};
use homomorphic_poly_commit::marlin_kzg::KZG10;
use index_private_marlin::Marlin;
use proof_of_function_relation::t_functional_triple::TFT;
use rand_chacha::ChaChaRng;

use index_private_marlin::data_structures::{Proof as MarlinProof};
use index_private_marlin::data_structures::{VerifierKey as MarlinVerifierKey};
use ark_serialize::CanonicalDeserialize;

type FS = SimpleHashFiatShamirRng<Blake2s, ChaChaRng>;
use ac_compiler::circuit_compiler::{CircuitCompiler, VanillaCompiler};

// use crate::{diag_test, slt_test};

type F = Fr;
type PC = KZG10<Bn254>;

type MarlinInst = Marlin<Fr, PC, FS>;


fn read_binary_data(file_path: &str) -> io::Result<Vec<u8>> {
    let mut file = match File::open(file_path) {
        Ok(file) => file,
        Err(e) => return Err(e),
    };

    let mut data = Vec::new();
    if let Err(e) = file.read_to_end(&mut data) {
        return Err(e);
    }

    Ok(data)
}

fn circuit_test_template<Func>(constraints: Func, inputs: &Vec<F>, outputs: &Vec<F>, proof_bin_filename: &String, vk_bin_filename: &String, tft_bin_filename: &String)
where
    Func: FnOnce(&mut ConstraintBuilder<F>) -> Result<(), Error>,
{
    let mut cb = ConstraintBuilder::<F>::new();

    let synthesized_circuit = Circuit::synthesize(constraints, &mut cb).unwrap();
    let (index_info, a, b, c) = VanillaCompiler::<F>::ac2tft(&synthesized_circuit);

    assert_eq!(true, index_info.check_domains_sizes::<F>());

    let domain_k =
        GeneralEvaluationDomain::<F>::new(index_info.number_of_non_zero_entries).unwrap();
    let domain_h = GeneralEvaluationDomain::<F>::new(index_info.number_of_constraints).unwrap();

    slt_test!(a, index_info.number_of_input_rows);
    slt_test!(b, index_info.number_of_input_rows);
    diag_test!(c);

    let rng = &mut test_rng();

    let universal_srs = MarlinInst::universal_setup(&index_info, rng).unwrap();

    let (pk, _vk) = MarlinInst::index(&universal_srs, &index_info, a, b, c, rng).unwrap();

    let serialized_vk = read_binary_data(vk_bin_filename).unwrap();
    let vk = MarlinVerifierKey::<F, PC>::deserialize(&*serialized_vk).unwrap();

    let serialized_proof = read_binary_data(proof_bin_filename).unwrap();
    let proof = MarlinProof::<F, PC>::deserialize(&*serialized_proof).unwrap();

    let serialized_tft = read_binary_data(tft_bin_filename).unwrap();
    let tft_proof = serialized_tft;

    // let verifier_well_formation_commits = Vec::new();
    // let commitment_labels = ["pi_lde.bin", "vh_gt_x.bin", "output_lde.bin", "vh_lt_y.bin"];
    // for label in &commitment_labels {
    //     let serialized_commitment = read_binary_data( label ).unwrap();
    //     let commitment =  PCCommitment::deserialize(&*serialized_commitment).unwrap();
    //     let labbeled_commitment = LabeledCommitment::new(label, commitment.clone(), None);
    //     verifier_well_formation_commits.push(labbeled_commitment);
    // }
    // assert!(MarlinInst::_verify(&vk, inputs, outputs, proof, rng, verifier_well_formation_commits).unwrap());
    assert!(MarlinInst::verify(&vk, inputs, outputs, proof, rng, &pk.committer_key).unwrap());
    
    // TEST PROOF OF FUNCTION
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

    let is_valid = TFT::<F, PC, FS>::verify(
        &vk.verifier_key,
        &pk.committer_key,
        index_info.number_of_input_rows,
        &commits[1],
        &commits[0],
        &commits[4],
        &commits[3],
        &commits[6],
        &commits[7],
        &commits[8],
        Some(domain_k.size() + 1),
        &domain_h,
        &domain_k,
        tft_proof,
        &mut fs_rng,
    );

    assert!(is_valid.is_ok());
    println!("Verify Success!")
    
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

    let _ = cb.enforce_constraint(&out, &one, GateType::Mul, VariableType::Output)?;

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    let proof_bin_filename = &args[1];
    let vk_bin_filename = &args[2];
    let tft_bin_filename = &args[3];

    let input_a: i32 = args[4].parse().unwrap();
    let input_b: i32 = args[5].parse().unwrap();
    let output: i32 = args[6].parse().unwrap();
    
    // let a_val = vec![ F::from(1), F::from(0), F::from(1)];
    // let b_val = vec![ F::from(0), F::from(1), F::from(0)];
    let a_val :Vec<_> = (0..3).map (|n| F::from((input_a >> n) & 1)).collect();
    let b_val :Vec<_> = (0..3).map (|n| F::from((input_b >> n) & 1)).collect();
    let expected_output = F::from(output);

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

    circuit_test_template(constraints, &inputs, &outputs, proof_bin_filename, vk_bin_filename, tft_bin_filename);
}
