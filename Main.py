import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

APP_SALT = b'docx_crypto_salt_2026'
AES_KEY_SIZE = 16       
HASH_ITERATIONS = 120000

def generate_aes_key(user_pass: str) -> bytes:
    """Menghasilkan kunci standar AES dari password inputan pengguna."""
    return PBKDF2(user_pass, APP_SALT, dkLen=AES_KEY_SIZE, count=HASH_ITERATIONS)

def encrypt_document(source_file: str, secret_pass: str):
    """Proses enkripsi AES mode CBC untuk file DOCX."""
    if not os.path.exists(source_file):
        print(f"[!] Error: File '{source_file}' tidak ditemukan.")
        return

    aes_key = generate_aes_key(secret_pass)
    cipher_engine = AES.new(aes_key, AES.MODE_CBC)
    
    with open(source_file, 'rb') as file_in:
        raw_data = file_in.read()
        
    padded_data = pad(raw_data, AES.block_size)
    encrypted_bytes = cipher_engine.encrypt(padded_data)
    
    output_name = source_file + ".enc"
    with open(output_name, 'wb') as file_out:
        file_out.write(cipher_engine.iv)
        file_out.write(encrypted_bytes)
        
    print(f"[*] ENCRYPTION SUCCESS : {source_file} -> {output_name}")

def decrypt_document(encrypted_file: str, secret_pass: str):
    """Proses dekripsi AES mode CBC untuk mengembalikan file DOCX."""
    if not os.path.exists(encrypted_file):
        print(f"[!] Error: File '{encrypted_file}' tidak ditemukan.")
        return

    aes_key = generate_aes_key(secret_pass)
    
    with open(encrypted_file, 'rb') as file_in:
        iv_vector = file_in.read(16)
        cipher_data = file_in.read()
        
    cipher_engine = AES.new(aes_key, AES.MODE_CBC, iv=iv_vector)
    
    try:
        decrypted_padded = cipher_engine.decrypt(cipher_data)
        original_data = unpad(decrypted_padded, AES.block_size)
        
        decrypted_name = encrypted_file.replace(".enc", "_decrypted.docx")
        with open(decrypted_name, 'wb') as file_out:
            file_out.write(original_data)
            
        print(f"[*] DECRYPTION SUCCESS : {encrypted_file} -> {decrypted_name}")
        
    except ValueError:
        print("[!] DECRYPTION FAILED: Password salah atau file rusak!")

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    print("-----------------------------------------")
    print("       DOCX ENCRYPTION TOOL (AES)        ")
    print("-----------------------------------------")
    
    target_docx = input("Enter DOCX filename (contoh: tugas.docx) : ")
    user_password = input("Enter secret password                    : ")
    
    print("\n[ Processing... ]")
    
    if os.path.exists(target_docx):
        encrypt_document(target_docx, user_password)
        
        encrypted_docx = target_docx + ".enc"
        decrypt_document(encrypted_docx, user_password)
    else:
        print(f"[!] Target file '{target_docx}' tidak ada di folder.")
        
    print("-----------------------------------------")