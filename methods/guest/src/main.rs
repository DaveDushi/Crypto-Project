use risc0_zkvm::guest::env;
use k256::{ecdsa::{signature::Verifier, Signature, VerifyingKey}, EncodedPoint,};


fn main() {
    // TODO: Implement your guest code here

    // read the input
    let (signature, encoded_verifying_key, message): (Signature, EncodedPoint, &[u8])= env::read();

    
    let verifying_key = VerifyingKey::from_encoded_point(&encoded_verifying_key).unwrap();
    verifying_key
        .verify(&message, &signature)
        .expect("ECDSA signature verification failed");

    env::commit(&message);
}
