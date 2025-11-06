from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

print("--- RSA Encryption Script Starting ---")

print("Generating 2048-bit RSA key pair...")
key = RSA.generate(2048)

private_key = key.export_key()
with open("private.pem", "wb") as f:
    f.write(private_key)
print("Private key saved to private.pem")

public_key = key.publickey().export_key()
with open("public.pem", "wb") as f:
    f.write(public_key)
print("Public key saved to public.pem")


print("\nEncrypting message.txt...")

with open("message.txt", "rb") as f:
    plaintext = f.read()

recipient_key = RSA.import_key(open("public.pem").read())

cipher_rsa = PKCS1_OAEP.new(recipient_key)

if len(plaintext) > 214:
    print(f"WARNING: The file is {len(plaintext)} bytes long. RSA can only encrypt data up to ~214 bytes with a 2048-bit key.")
    print("This encryption might fail. For this assignment, it's a good demonstration of RSA's limitations.")

encrypted_data = cipher_rsa.encrypt(plaintext)

with open("message_rsa_encrypted.bin", "wb") as f:
    f.write(encrypted_data)

print(f"File encrypted successfully! Output saved to message_rsa_encrypted.bin")
print("\n--- Script Finished ---")

original_size = os.path.getsize("message.txt")
encrypted_size = os.path.getsize("message_rsa_encrypted.bin")
print(f"\nOriginal file size: {original_size} bytes")
print(f"Encrypted file size: {encrypted_size} bytes (256 bytes for a 2048-bit key)")

print("\n--- RSA Decryption Script Starting ---")

private_key_loaded = RSA.import_key(open("private.pem").read())

with open("message_rsa_encrypted.bin", "rb") as f:
    encrypted_data = f.read()


cipher_rsa_decrypt = PKCS1_OAEP.new(private_key_loaded)

decrypted_data = cipher_rsa_decrypt.decrypt(encrypted_data)

with open("message_rsa_decrypted.txt", "wb") as f:
    f.write(decrypted_data)

print(f"File decrypted successfully! Output saved to message_rsa_decrypted.txt")


with open("message.txt", "r") as f_orig:
    original_content = f_orig.read()

with open("message_rsa_decrypted.txt", "r") as f_dec:
    decrypted_content = f_dec.read()

if original_content == decrypted_content:
    print("\nVerification SUCCESS: The decrypted content matches the original message.")
else:
    print("\nVerification FAILED: The decrypted content does not match the original.")

print("\n--- Decryption Finished ---")