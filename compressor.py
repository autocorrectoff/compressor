import os
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_file_map(input_dir):
    file_map = {}
    for root, _, files in os.walk(input_dir):
        for file in files:
            filepath = os.path.join(root, file)
            relpath = os.path.relpath(filepath, input_dir)
            with open(filepath, 'rb') as f:
                file_map[relpath] = f.read()
    return file_map

def encrypt_data(data: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, None)
    return nonce + ct  # Prepend nonce for later decryption

def main():
    input_dir = os.path.join(os.path.dirname(__file__), 'input')  # change if needed
    output_file = 'output.jsonl'

    # 32 bytes key (256-bit AES)
    key = AESGCM.generate_key(bit_length=256)
    print(f"Save this key to decrypt later: {base64.urlsafe_b64encode(key).decode()}")

    file_map = generate_file_map(input_dir)

    with open(output_file, 'w') as f:
        for path, content in file_map.items():
            enc_path = encrypt_data(path.encode(), key)
            enc_content = encrypt_data(content, key)
            record = {
                'key': base64.b64encode(enc_path).decode(),
                'value': base64.b64encode(enc_content).decode()
            }
            f.write(json.dumps(record) + '\n')

    print(f"Encryption complete. Output: {output_file}")

if __name__ == "__main__":
    main()
