#![allow(clippy::assertions_on_result_states)]
use ark_bn254::Fr;
use ark_bn254::G1Projective;
use libspartan::{InputsAssignment, NIZKGens, VarsAssignment, NIZK, circom_reader::{load_as_spartan_inst, load_witness_from_bin_reader}};
use merlin::Transcript;
use std::env::current_dir;
use std::path::PathBuf;
use std::time::Instant;

#[allow(non_snake_case)]
fn main() {
  let r1cs_path = "examples/vc_and_disclose/vc_and_disclose.r1cs";
  let witness_path = "examples/vc_and_disclose/witness.wtns";
  let num_pub_inputs = 10;

  let circom_r1cs_path = PathBuf::from(r1cs_path);
  let circom_wtns_path = PathBuf::from(witness_path);

  let root = current_dir().unwrap();
  let circom_r1cs_path = root.join(circom_r1cs_path);
  let circom_wtns_path = root.join(circom_wtns_path);

  let spartan_inst = load_as_spartan_inst(circom_r1cs_path, num_pub_inputs);
  let witness = load_witness_from_bin_reader(std::fs::File::open(circom_wtns_path).unwrap()).unwrap();

  let assignment = VarsAssignment::new(&witness).unwrap();

  // produce public parameters
  let gens = NIZKGens::<G1Projective>::new(
    spartan_inst.inst.get_num_cons(), 
    spartan_inst.inst.get_num_vars(), 
    spartan_inst.inst.get_num_inputs()
  );

  // produce a proof of satisfiability
  let mut prover_transcript = Transcript::new(b"nizk_example");

  let mut inputs = vec![Fr::from(0); spartan_inst.inst.get_num_inputs()];
  for i in 0..spartan_inst.inst.get_num_inputs() {
      inputs[i] = witness[i];
  }
  let inputs = InputsAssignment::new(&inputs).unwrap();

  let start_proving = Instant::now();
  let proof = NIZK::prove(
    &spartan_inst,
    assignment.clone(),
    &inputs,
    &gens,
    &mut prover_transcript,
  );
  let proving_time = start_proving.elapsed();
  println!("Proving time: {:?}", proving_time);

  use ark_serialize::{CanonicalSerialize, Compress};

  // log proof size
  let proof_size = proof.r1cs_sat_proof.serialized_size(Compress::Yes);
  println!("Proof size: {} bytes", proof_size);

  // verify the proof of satisfiability
  let mut verifier_transcript = Transcript::new(b"nizk_example");
  let start_verification = Instant::now();
  assert!(proof
    .verify(&spartan_inst, &inputs, &mut verifier_transcript, &gens)
    .is_ok());
  let verification_time = start_verification.elapsed();
  println!("Verification time: {:?}", verification_time);

  println!("proof verification successful!");
}
