from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

print("--- AES-256 Symmetric Encryption Script Starting ---")
print("Target file: message_aes.txt")

aes_key = get_random_bytes(32)
with open("aes_key.bin", "wb") as f:
    f.write(aes_key)
print("AES key generated and saved to aes_key.bin")

iv = get_random_bytes(16)
with open("aes_iv.bin", "wb") as f:
    f.write(iv)
print("AES IV generated and saved to aes_iv.bin")

with open("message_aes.txt", "rb") as f:
    plaintext_aes = f.read()

cipher_aes_encrypt = AES.new(aes_key, AES.MODE_CBC, iv)

padded_plaintext = pad(plaintext_aes, AES.block_size)
ciphertext_aes = cipher_aes_encrypt.encrypt(padded_plaintext)

with open("message_aes_encrypted.bin", "wb") as f:
    f.write(ciphertext_aes)
print(f"\nFile encrypted with AES! Output saved to message_aes_encrypted.bin")

with open("message_aes_encrypted.bin", "rb") as f:
    ciphertext_to_decrypt = f.read()

cipher_aes_decrypt = AES.new(aes_key, AES.MODE_CBC, iv)

decrypted_padded_data = cipher_aes_decrypt.decrypt(ciphertext_to_decrypt)
decrypted_data_aes = unpad(decrypted_padded_data, AES.block_size)

with open("message_aes_decrypted.txt", "wb") as f:
    f.write(decrypted_data_aes)

print(f"File decrypted with AES! Output saved to message_aes_decrypted.txt")

if plaintext_aes == decrypted_data_aes:
    print("\nVerification SUCCESS: The AES-decrypted content matches the message_aes.txt content.")
else:
    print("\nVerification FAILED: The AES-decrypted content does not match.")

print("\n--- AES Script Finished ---")