from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature

# Generate private and public keys using SECP256K1
def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256K1())
    public_key = private_key.public_key()
    return private_key, public_key

# Save keys to files
def save_keys(private_key, public_key):
    # Private key in PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open("private_key.pem", "wb") as private_file:
        private_file.write(private_pem)

    # Public key in PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("public_key.pem", "wb") as public_file:
        public_file.write(public_pem)

# Sign a message with the private key
def sign_message(private_key, message):
    signature = private_key.sign(
        message.encode(),  # Encoding the message to bytes
        ec.ECDSA(hashes.SHA256())
    )
    return signature

# Verify the signature with the public key
def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message.encode(),  # Encoding the message to bytes
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False

# Main function
if __name__ == "__main__":
    message = "This is a secure message"
    
    # Generate keys
    private_key, public_key = generate_keys()
    private_key_1, public_key_1 = generate_keys()
    
    # Save keys to files
    save_keys(private_key, public_key)
    print("Private and Public keys saved.")
    
    # Sign the message
    signature = sign_message(private_key, message)
    print(f"Message: {message}")
    print(f"Signature: {signature.hex()}")

    # Verify the signature
    is_valid = verify_signature(public_key_1, message, signature)
    if is_valid:
        print("The signature is valid!")
    else:
        print("The signature is invalid.")
