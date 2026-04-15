
from cryptography.hazmat.primitives.asymmetric import ed448

def generate_ed448_signature(private_key_hex, message_hex):
    priv_bytes = bytes.fromhex(private_key_hex)
    msg_bytes = bytes.fromhex(message_hex)
    private_key = ed448.Ed448PrivateKey.from_private_bytes(priv_bytes)
    return private_key.sign(msg_bytes).hex()

if __name__ == "__main__":
    print("Ed448 is being tested.")

