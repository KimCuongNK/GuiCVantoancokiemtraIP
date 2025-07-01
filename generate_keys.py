# generate_keys.py
from Crypto.PublicKey import RSA

# Kích thước khóa 2048-bit được khuyến nghị để tương thích với RSA-OAEP và SHA-512
KEY_SIZE = 2048 

# --- Cấu hình số lượng khóa cần tạo ---
# Thay đổi các giá trị này để tạo số lượng người gửi/người nhận mong muốn
NUM_SENDERS = 1  # Ví dụ: Tạo khóa cho 1 người gửi (sender1)
NUM_RECEIVERS = 1 # Ví dụ: Tạo khóa cho 1 người nhận (receiver1)

def generate_key_pair(entity_type, index):
    """
    Tạo một cặp khóa RSA và lưu vào file với tên có tiền tố.
    Args:
        entity_type (str): Loại thực thể (ví dụ: "sender" hoặc "receiver").
        index (int): Chỉ số của thực thể (ví dụ: 1, 2, ...).
    """
    key = RSA.generate(KEY_SIZE)
    private_filename = f"{entity_type}{index}_private.pem"
    public_filename = f"{entity_type}{index}_public.pem"

    # Lưu khóa riêng tư
    with open(private_filename, "wb") as f:
        f.write(key.export_key('PEM'))
    print(f"Đã tạo file khóa riêng tư: {private_filename}")

    # Lưu khóa công khai
    public_key = key.publickey()
    with open(public_filename, "wb") as f:
        f.write(public_key.export_key('PEM'))
    print(f"Đã tạo file khóa công khai: {public_filename}")

print(f"Bắt đầu tạo khóa {KEY_SIZE}-bit...")

# --- Tạo khóa cho Người Gửi (Applicants) ---
for i in range(1, NUM_SENDERS + 1):
    print(f"\n--- Tạo khóa cho Người Gửi {i} ---")
    generate_key_pair("sender", i)

# --- Tạo khóa cho Người Nhận (Companies/Receivers) ---
for i in range(1, NUM_RECEIVERS + 1):
    print(f"\n--- Tạo khóa cho Người Nhận {i} ---")
    generate_key_pair("receiver", i)

print(f"\nĐã tạo xong tổng cộng {NUM_SENDERS * 2 + NUM_RECEIVERS * 2} file khóa {KEY_SIZE}-bit.")
