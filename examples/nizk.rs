#![allow(clippy::assertions_on_result_states)]
use curve25519_dalek::scalar::Scalar;
use libspartan::{InputsAssignment, NIZKGens, VarsAssignment, NIZK, Instance
  // circom_reader::{load_as_spartan_inst, load_witness_from_bin_reader}
  };
use merlin::Transcript;
// use std::env::current_dir;
// use std::path::PathBuf;
use std::time::Instant;
// use ark_serialize::{CanonicalSerialize, Compress};
use rand::rngs::OsRng;
// use serde::ser::Serialize;

#[allow(non_snake_case)]
fn produce_r1cs() -> (
  usize,
  usize,
  usize,
  usize,
  Instance,
  VarsAssignment,
  InputsAssignment,
) {
  // parameters of the R1CS instance
  let num_cons = 4;
  let num_vars = 4;
  let num_inputs = 1;
  let num_non_zero_entries = 8;

  // We will encode the above constraints into three matrices, where
  // the coefficients in the matrix are in the little-endian byte order
  let mut A: Vec<(usize, usize, [u8; 32])> = Vec::new();
  let mut B: Vec<(usize, usize, [u8; 32])> = Vec::new();
  let mut C: Vec<(usize, usize, [u8; 32])> = Vec::new();

  let one = Scalar::ONE.to_bytes();

  // R1CS is a set of three sparse matrices A B C, where is a row for every
  // constraint and a column for every entry in z = (vars, 1, inputs)
  // An R1CS instance is satisfiable iff:
  // Az \circ Bz = Cz, where z = (vars, 1, inputs)

  // constraint 0 entries in (A,B,C)
  // constraint 0 is Z0 * Z0 - Z1 = 0.
  A.push((0, 0, one));
  B.push((0, 0, one));
  C.push((0, 1, one));

  // constraint 1 entries in (A,B,C)
  // constraint 1 is Z1 * Z0 - Z2 = 0.
  A.push((1, 1, one));
  B.push((1, 0, one));
  C.push((1, 2, one));

  // constraint 2 entries in (A,B,C)
  // constraint 2 is (Z2 + Z0) * 1 - Z3 = 0.
  A.push((2, 2, one));
  A.push((2, 0, one));
  B.push((2, num_vars, one));
  C.push((2, 3, one));

  // constraint 3 entries in (A,B,C)
  // constraint 3 is (Z3 + 5) * 1 - I0 = 0.
  A.push((3, 3, one));
  A.push((3, num_vars, Scalar::from(5u32).to_bytes()));
  B.push((3, num_vars, one));
  C.push((3, num_vars + 1, one));

  let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C).unwrap();

  // compute a satisfying assignment
  let mut csprng: OsRng = OsRng;
  let z0 = Scalar::random(&mut csprng);
  let z1 = z0 * z0; // constraint 0
  let z2 = z1 * z0; // constraint 1
  let z3 = z2 + z0; // constraint 2
  let i0 = z3 + Scalar::from(5u32); // constraint 3

  // create a VarsAssignment
  let mut vars = vec![Scalar::ZERO.to_bytes(); num_vars];
  vars[0] = z0.to_bytes();
  vars[1] = z1.to_bytes();
  vars[2] = z2.to_bytes();
  vars[3] = z3.to_bytes();
  let assignment_vars = VarsAssignment::new(&vars).unwrap();

  // create an InputsAssignment
  let mut inputs = vec![Scalar::ZERO.to_bytes(); num_inputs];
  inputs[0] = i0.to_bytes();
  let assignment_inputs = InputsAssignment::new(&inputs).unwrap();

  // check if the instance we created is satisfiable
  let res = inst.is_sat(&assignment_vars, &assignment_inputs);
  assert!(res.unwrap(), "should be satisfied");

  (
    num_cons,
    num_vars,
    num_inputs,
    num_non_zero_entries,
    inst,
    assignment_vars,
    assignment_inputs,
  )
}

#[allow(non_snake_case)]
fn main() {
  let (
    num_cons,
    num_vars,
    num_inputs,
    num_non_zero_entries,
    inst,
    assignment_vars,
    assignment_inputs,
  ) = produce_r1cs();

  let gens = NIZKGens::new(
    num_cons,
    num_vars,
    num_inputs,
  );

  // produce a proof of satisfiability
  let mut prover_transcript = Transcript::new(b"nizk_example");

  let start_proving = Instant::now();
  let proof = NIZK::prove(
    &inst,
    assignment_vars,
    &assignment_inputs,
    &gens,
    &mut prover_transcript,
  );
  let proving_time = start_proving.elapsed();
  println!("Proving time: {:?}", proving_time);

  // Serialize the proof, instance, and inputs
  // let mut serialized_proof = Vec::new();
  // proof.serialize_compressed(&mut serialized_proof).unwrap();

  // let mut serialized_spartan_inst = Vec::new();
  // spartan_inst.inst.serialize_compressed(&mut serialized_spartan_inst).unwrap();

  // let mut serialized_inputs = Vec::new();
  // inputsMap.serialize_compressed(&mut serialized_inputs).unwrap();
  
  let spartan_inst_bytes = bincode::serialize(&inst).unwrap();
  std::fs::write("spartan_inst.bin", &spartan_inst_bytes).unwrap();

  // Serialize proof
  let proof_bytes = bincode::serialize(&proof).unwrap();
  std::fs::write("proof.bin", &proof_bytes).unwrap();

  // Serialize inputs
  let inputs_bytes = bincode::serialize(&assignment_inputs).unwrap();
  std::fs::write("inputs.bin", &inputs_bytes).unwrap();

  println!("Serialized spartan_inst, proof, and inputs to files.");

  // log proof size
  let proof_size = bincode::serialized_size(&proof).unwrap();
  println!("Proof size: {} bytes", proof_size);

  // verify the proof of satisfiability
  let mut verifier_transcript = Transcript::new(b"nizk_example");
  let start_verification = Instant::now();
  assert!(proof
    .verify(&inst, &assignment_inputs, &mut verifier_transcript, &gens)
    .is_ok());
  let verification_time = start_verification.elapsed();
  println!("Verification time: {:?}", verification_time);

  println!("proof verification successful!");
}
