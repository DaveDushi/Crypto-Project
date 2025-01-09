use methods::{FINAL_GUEST_ELF, FINAL_GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};
use std::fs;
use k256::{
    ecdsa::{SigningKey, Signature, signature::Signer, VerifyingKey},
};
use hex::{ encode, decode };


fn generate_keys() -> (SigningKey, VerifyingKey) {
    let private_key = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
    let private_key_bytes = decode(private_key).expect("Failed to decode hex");

    let signing_key = SigningKey::from_slice(&private_key_bytes)
    .expect("Failed to create signing key");
    

    let verifying_key: VerifyingKey = VerifyingKey::from(&signing_key);

    return (signing_key, verifying_key)
}

fn sign_message(signing_key: &SigningKey, message: &[u8]) -> Signature {
    signing_key.sign(message)
}



fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let message: &[u8] = b"This is a test of the tsunami alert system.";

    let (ecdsa_signing_key, ecdsa_verifying_key) = generate_keys();
    let ecdsa_signature = sign_message(&ecdsa_signing_key, message);
    println!("{}", encode(ecdsa_signing_key.to_bytes()));
    
    let input = (ecdsa_signature, ecdsa_verifying_key.to_encoded_point(false), message);
    println!("{:?}",input);
    // Create the environment with input data
    let env = ExecutorEnv::builder()
        .write(&input) 
        .unwrap()
        .build()
        .unwrap();

    // Obtain the default prover
    let prover = default_prover();

    // Prove
    let prove_info = prover
        .prove(env, FINAL_GUEST_ELF)
        .unwrap();

    let receipt = prove_info.receipt;

    // Decode output
    let output: String = receipt.journal.decode().unwrap();
    
    println!("Decoded journal output: {}", output);

    // Verify receipt
    receipt.verify(FINAL_GUEST_ID).unwrap();
}