import os
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Function to load private key from file
def load_private_key(file_path):
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    return private_key

# Function to generate a random challenge (e.g., a random string or number)
def generate_challenge():
    # Generate a random 32-byte challenge (you can change this size or method)
    challenge = os.urandom(32)
    return challenge

# Function to sign the challenge
def sign_challenge(private_key, challenge):
    # Sign the challenge with ECDSA (using SECP256R1 curve)
    signature = private_key.sign(
        challenge,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

# Function to save the challenge and signature to files
def save_files(challenge, signature):
    # Save the challenge to 'challenge.txt'
    with open("challenge.txt", "wb") as challenge_file:
        challenge_file.write(challenge)

    # Save the signature to 'challenge.txt.sig'
    with open("challenge.txt.sig", "wb") as signature_file:
        signature_file.write(signature)

def main():
    # Load the private key from the PEM file
    private_key = load_private_key("alice_private_key.pem")

    # Generate a random challenge
    challenge = generate_challenge()

    # Sign the challenge with the private key
    signature = sign_challenge(private_key, challenge)

    # Save the challenge and signature to files
    save_files(challenge, signature)

    print("Challenge and signature have been saved to 'challenge.txt' and 'challenge.txt.sig'.")

if __name__ == "__main__":
    main()
