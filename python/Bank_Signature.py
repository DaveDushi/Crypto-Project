from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
import base64

# Generate a public private key pair using Elliptic Curve Cryptography (ECC) SECP256K1
def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256K1())
    public_key = private_key.public_key()
    return private_key, public_key

# Save Keys
def save_key_to_file(key, file_path, is_private=False):
    encoding = serialization.Encoding.PEM
    if is_private:
        serialized = key.private_bytes(
            encoding=encoding,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    else:
        serialized = key.public_bytes(
            encoding=encoding,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    with open(file_path, "wb") as f:
        f.write(serialized)

# Create and Sign the File
def create_and_sign_file(banks_private_key, clients_public_key, clients_balance, file_path):
    # Generate the text content
    text = f"Balance: {clients_balance}\nPublic Key: {clients_public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()}"
    # Save the text content to a file
    with open(file_path, "wb") as f:
        f.write(text.encode())
    
    # Sign the file content
    signature = banks_private_key.sign(
        text.encode(),
        ec.ECDSA(hashes.SHA256())
    )
    
    # Save the signature
    with open(file_path + ".sig", "wb") as f:
        f.write(signature)
    print("File and signature created successfully.")

# Main execution
bank_private_key, bank_public_key = generate_keys()
# save_key_to_file(bank_private_key, "bank_private_key.pem", is_private=True)
save_key_to_file(bank_public_key, "bank_public_key.pem", is_private=False)

alice_private_key, alice_public_key = generate_keys()
save_key_to_file(alice_private_key, "alice_private_key.pem", is_private=True)
# save_key_to_file(alice_public_key, "alice_public_key.pem", is_private=False)


create_and_sign_file(bank_private_key, alice_public_key, 100, "balance.txt")

