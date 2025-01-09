use risc0_zkvm::guest::env;
use k256::{ecdsa::{signature::Verifier, Signature, VerifyingKey}, EncodedPoint,};


fn main() {
    // TODO: Implement your guest code here

    // read the input
    let (signature, verifying_key): (Signature, EncodedPoint)= env::read();

    // TODO: do something with the input
    let message = "hello";
    // write public output to the journal
    env::commit(&message);
}
