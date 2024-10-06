#![allow(clippy::assertions_on_result_states)]
use libspartan::{NIZKGens, NIZK, Instance
  // circom_reader::{load_as_spartan_inst, load_witness_from_bin_reader}
};
use merlin::Transcript;
// use std::env::current_dir;
// use std::path::PathBuf;
use std::time::Instant;

#[allow(non_snake_case)]
fn main() {
  let num_cons = 8192;
  let num_vars = 8192;
  let num_inputs = 64;

  let (inst, assignment_vars, assignment_inputs) = Instance::produce_synthetic_r1cs(num_cons, num_vars, num_inputs);

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
