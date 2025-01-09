from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature



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

    with open("bank_public_key.pem", "rb") as f:
        public_key_byte = f.read()

    with open("balance.txt.sig", "rb") as f:
        signature = f.read()
    
    with open("balance.txt", "rb") as f:
        message = f.read()
    
    print(f"Signature: {signature.hex()}")
    print(message.decode())

    # a ECC public key
    public_key = serialization.load_pem_public_key(public_key_byte)

    # Verify the signature
    is_valid = verify_signature(public_key, message.decode(), signature)
    if is_valid:
        print("The signature is valid!")
    else:
        print("The signature is invalid.")
