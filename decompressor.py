import os
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def decrypt_data(enc_data: bytes, key: bytes) -> bytes:
    nonce = enc_data[:12]
    ct = enc_data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

def main():
    input_file = 'output.jsonl'
    output_dir = 'restored_source_code'

    key_b64 = input("Enter the decryption key: ")
    key = base64.urlsafe_b64decode(key_b64)

    os.makedirs(output_dir, exist_ok=True)

    with open(input_file, 'r') as f:
        for line in f:
            record = json.loads(line)
            enc_path = base64.b64decode(record['key'])
            enc_content = base64.b64decode(record['value'])

            path = decrypt_data(enc_path, key).decode()
            content = decrypt_data(enc_content, key)

            full_path = os.path.join(output_dir, path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, 'wb') as out_file:
                out_file.write(content)

    print(f"Decryption and unpacking complete. Files restored to: {output_dir}")

if __name__ == "__main__":
    main()
