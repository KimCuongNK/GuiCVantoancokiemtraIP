# crypto_utils.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import os

# --- Key Generation ---
def generate_rsa_key_pair(key_size=2048, private_filename="private.pem", public_filename="public.pem"):
    """
    Generates an RSA key pair and saves them to specified files.
    Tạo một cặp khóa RSA và lưu chúng vào các file được chỉ định.
    Args:
        key_size (int): The size of the RSA key in bits (e.g., 2048).
                        Kích thước của khóa RSA theo bit (ví dụ: 2048).
        private_filename (str): The filename for the private key.
                                Tên file cho khóa riêng tư.
        public_filename (str): The filename for the public key.
                               Tên file cho khóa công khai.
    Returns:
        tuple: (RSA private key object, RSA public key object)
               (Đối tượng khóa riêng tư RSA, Đối tượng khóa công khai RSA)
    """
    key = RSA.generate(key_size)
    private_key = key
    public_key = key.publickey()

    with open(private_filename, "wb") as f:
        f.write(private_key.export_key('PEM'))
    print(f"Đã tạo file khóa riêng tư: {private_filename}")

    with open(public_filename, "wb") as f:
        f.write(public_key.export_key('PEM'))
    print(f"Đã tạo file khóa công khai: {public_filename}")
    
    return private_key, public_key

def load_rsa_private_key(filepath):
    """
    Loads an RSA private key from a .pem file.
    Tải khóa riêng tư RSA từ một file .pem.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Không tìm thấy file khóa riêng tư: {filepath}")
    with open(filepath, "rb") as f:
        private_key = RSA.import_key(f.read())
    return private_key

def load_rsa_public_key(filepath):
    """
    Loads an RSA public key from a .pem file.
    Tải khóa công khai RSA từ một file .pem.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Không tìm thấy file khóa công khai: {filepath}")
    with open(filepath, "rb") as f:
        public_key = RSA.import_key(f.read())
    return public_key

# --- Encryption and Decryption (Sender Side) ---
def encrypt_data_sender(data_bytes, receiver_public_key_obj):
    """
    Encrypts data using AES with a randomly generated session key,
    and encrypts the session key with the receiver's RSA public key (OAEP).
    Also generates an IV and calculates a SHA512 hash of IV+ciphertext.
    
    Mã hóa dữ liệu bằng AES với khóa phiên được tạo ngẫu nhiên,
    và mã hóa khóa phiên bằng khóa công khai RSA của người nhận (OAEP).
    Cũng tạo IV và tính toán hàm băm SHA512 của IV+ciphertext.
    
    Args:
        data_bytes (bytes): The data to encrypt (e.g., file content).
                            Dữ liệu cần mã hóa (ví dụ: nội dung file).
        receiver_public_key_obj (Crypto.PublicKey.RSA._RSAobj): The receiver's public key object.
                                                                Đối tượng khóa công khai của người nhận.
        
    Returns:
        tuple: (encrypted_session_key (bytes), iv (bytes), ciphertext (bytes), integrity_hash (str))
               (khóa phiên đã mã hóa (bytes), iv (bytes), văn bản mã hóa (bytes), hash toàn vẹn (str))
    """
    session_key = get_random_bytes(16)  # AES-128 key
    iv = get_random_bytes(AES.block_size) # AES block size is 16 bytes for CBC

    # Encrypt session key with receiver's public key
    # Mã hóa khóa phiên bằng khóa công khai của người nhận
    cipher_rsa = PKCS1_OAEP.new(receiver_public_key_obj, hashAlgo=SHA512)
    encrypted_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt data with AES
    # Mã hóa dữ liệu bằng AES
    cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
    ciphertext = cipher_aes.encrypt(pad(data_bytes, AES.block_size))

    # Calculate integrity hash of IV + ciphertext
    # Tính toán hàm băm toàn vẹn của IV + ciphertext
    integrity_hash = SHA512.new(iv + ciphertext).hexdigest()

    return encrypted_session_key, iv, ciphertext, integrity_hash

# --- Decryption (Receiver Side) ---
def decrypt_data_receiver(encrypted_session_key, iv, ciphertext, receiver_private_key_obj):
    """
    Decrypts the session key using the receiver's RSA private key,
    then decrypts the ciphertext using the recovered session key and IV.
    
    Giải mã khóa phiên bằng khóa riêng tư RSA của người nhận,
    sau đó giải mã văn bản mã hóa bằng khóa phiên đã khôi phục và IV.
    
    Args:
        encrypted_session_key (bytes): The AES session key encrypted with RSA.
                                       Khóa phiên AES đã được mã hóa bằng RSA.
        iv (bytes): The initialization vector used for AES.
                    Vector khởi tạo được sử dụng cho AES.
        ciphertext (bytes): The encrypted data.
                            Dữ liệu đã mã hóa.
        receiver_private_key_obj (Crypto.PublicKey.RSA._RSAobj): The receiver's private key object.
                                                                Đối tượng khóa riêng tư của người nhận.
        
    Returns:
        bytes: The decrypted data.
               Dữ liệu đã giải mã.
    """
    # Decrypt session key with receiver's private key
    # Giải mã khóa phiên bằng khóa riêng tư của người nhận
    cipher_rsa = PKCS1_OAEP.new(receiver_private_key_obj, hashAlgo=SHA512)
    session_key = cipher_rsa.decrypt(encrypted_session_key)

    # Decrypt data with AES
    # Giải mã dữ liệu bằng AES
    cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)

    return decrypted_data

# --- Digital Signature (Sender Side) ---
def sign_data(data_bytes, sender_private_key_obj):
    """
    Signs data using the sender's RSA private key with PKCS1_v1.5 and SHA512.
    Ký dữ liệu bằng khóa riêng tư RSA của người gửi với PKCS1_v1.5 và SHA512.
    Args:
        data_bytes (bytes): The data to sign.
                            Dữ liệu cần ký.
        sender_private_key_obj (Crypto.PublicKey.RSA._RSAobj): The sender's private key object.
                                                                Đối tượng khóa riêng tư của người gửi.
    Returns:
        bytes: The digital signature.
               Chữ ký số.
    """
    h = SHA512.new(data_bytes)
    signature = pkcs1_15.new(sender_private_key_obj).sign(h)
    return signature

# --- Digital Signature Verification (Receiver Side) ---
def verify_signature(data_bytes, signature, sender_public_key_obj):
    """
    Verifies a digital signature using the sender's RSA public key with PKCS1_v1.5 and SHA512.
    Xác minh chữ ký số bằng khóa công khai RSA của người gửi với PKCS1_v1.5 và SHA512.
    Args:
        data_bytes (bytes): The original data that was signed.
                            Dữ liệu gốc đã được ký.
        signature (bytes): The digital signature to verify.
                           Chữ ký số cần xác minh.
        sender_public_key_obj (Crypto.PublicKey.RSA._RSAobj): The sender's public key object.
                                                                Đối tượng khóa công khai của người gửi.
    Returns:
        bool: True if the signature is valid, False otherwise.
              True nếu chữ ký hợp lệ, False nếu không.
    """
    h = SHA512.new(data_bytes)
    try:
        pkcs1_15.new(sender_public_key_obj).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# --- Hashing ---
def calculate_sha512_hash(data_bytes):
    """
    Calculates the SHA-512 hash of the given bytes.
    Tính toán hàm băm SHA-512 của các byte đã cho.
    """
    return SHA512.new(data_bytes).hexdigest()

if __name__ == '__main__':
    print("Đây là một tập lệnh tiện ích cho các hoạt động mã hóa.")
    print("Chạy generate_keys.py để tạo các file khóa.")
    print("Ví dụ sử dụng:")
    # Example: Generating keys
    # private_key, public_key = generate_rsa_key_pair(2048, "test_private.pem", "test_public.pem")

    # Example: Loading keys
    # loaded_private_key = load_rsa_private_key("test_private.pem")
    # loaded_public_key = load_rsa_public_key("test_public.pem")

    # Example: Encryption/Decryption flow
    # message = b"This is a secret message for testing."
    # enc_session_key, iv, cipher_text, integrity_hash = encrypt_data_sender(message, loaded_public_key)
    # print(f"\nKhóa phiên đã mã hóa: {base64.b64encode(enc_session_key)}")
    # print(f"IV: {base64.b64encode(iv)}")
    # print(f"Văn bản mã hóa: {base64.b64encode(cipher_text)}")
    # print(f"Hash toàn vẹn: {integrity_hash}")

    # decrypted_message = decrypt_data_receiver(enc_session_key, iv, cipher_text, loaded_private_key)
    # print(f"Tin nhắn đã giải mã: {decrypted_message.decode('utf-8')}")
    # print(f"Kiểm tra Hash (người gửi tính toán): {integrity_hash}")
    # print(f"Kiểm tra Hash (người nhận tính toán): {calculate_sha512_hash(iv + cipher_text)}")

    # Example: Signing/Verification flow
    # data_to_sign = b"This is data that needs to be signed."
    # signature = sign_data(data_to_sign, loaded_private_key)
    # print(f"\nChữ ký: {base64.b64encode(signature)}")
    # is_valid = verify_signature(data_to_sign, signature, loaded_public_key)
    # print(f"Chữ ký hợp lệ: {is_valid}")

    # Tamper with data_to_sign
    # tampered_data = b"This is data that needs to be signed. TAMPERED!"
    # is_valid_tampered = verify_signature(tampered_data, signature, loaded_public_key)
    # print(f"Chữ ký hợp lệ (dữ liệu bị giả mạo): {is_valid_tampered}")
