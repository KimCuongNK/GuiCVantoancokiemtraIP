# sender.py
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import socket
import json
import base64
import time
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import struct
import os
import threading

# --- Cấu hình mặc định ---
DEFAULT_PORT = 65432
DEFAULT_IP = '127.0.0.1' 

# Cấu hình file khóa mặc định
DEFAULT_SENDER_PRIVATE_KEY_FILE = 'sender1_private.pem'
DEFAULT_RECEIVER_PUBLIC_KEY_FILE = 'receiver1_public.pem'

class SenderApp:
    def __init__(self, master):
        self.master = master
        master.title("Ứng dụng Gửi CV An toàn")
        master.geometry("800x850")
        master.resizable(False, False)

        self.create_sender_widgets(master)
        self.update_chat_log_sender("Ứng dụng gửi đã sẵn sàng.", "info")

    # --- Các hàm tiện ích cho GUI ---
    def update_chat_log(self, text_widget, text, tag=None):
        """Cập nhật trạng thái vào ô văn bản cuộn."""
        current_time = datetime.now().strftime("[%H:%M:%S]")
        text_widget.insert(tk.END, f"{current_time} {text}\n", tag)
        text_widget.see(tk.END)
        print(f"{current_time} {text}") # In ra console để debug

    def clear_chat_log(self, text_widget):
        """Xóa nội dung trong ô văn bản chat log."""
        text_widget.delete(1.0, tk.END)
        self.update_chat_log(text_widget, "Nhật ký đã được xóa.", "info")

    # --- Giao diện Gửi CV ---
    def create_sender_widgets(self, parent_frame):
        # Configuration Frame
        config_frame = tk.LabelFrame(parent_frame, text="Cấu hình Gửi", padx=10, pady=10)
        config_frame.pack(pady=10, padx=10, fill="x")

        tk.Label(config_frame, text="Receiver Host:").grid(row=0, column=0, sticky="w", pady=2)
        self.sender_receiver_host_entry = tk.Entry(config_frame, width=40)
        self.sender_receiver_host_entry.grid(row=0, column=1, pady=2, padx=5)
        self.sender_receiver_host_entry.insert(0, DEFAULT_IP)

        tk.Label(config_frame, text="Receiver Port:").grid(row=1, column=0, sticky="w", pady=2)
        self.sender_receiver_port_entry = tk.Entry(config_frame, width=40)
        self.sender_receiver_port_entry.grid(row=1, column=1, pady=2, padx=5)
        self.sender_receiver_port_entry.insert(0, DEFAULT_PORT)

        tk.Label(config_frame, text="IP của tôi:").grid(row=2, column=0, sticky="w", pady=2)
        self.sender_my_ip_entry = tk.Entry(config_frame, width=40)
        self.sender_my_ip_entry.grid(row=2, column=1, pady=2, padx=5)
        self.sender_my_ip_entry.insert(0, DEFAULT_IP)

        tk.Label(config_frame, text="Khóa riêng tư Người gửi:").grid(row=3, column=0, sticky="w", pady=2)
        self.sender_private_key_entry = tk.Entry(config_frame, width=40)
        self.sender_private_key_entry.grid(row=3, column=1, pady=2, padx=5)
        self.sender_private_key_entry.insert(0, DEFAULT_SENDER_PRIVATE_KEY_FILE)

        tk.Label(config_frame, text="Khóa công khai Người nhận:").grid(row=4, column=0, sticky="w", pady=2)
        self.sender_receiver_public_key_entry = tk.Entry(config_frame, width=40)
        self.sender_receiver_public_key_entry.grid(row=4, column=1, pady=2, padx=5)
        self.sender_receiver_public_key_entry.insert(0, DEFAULT_RECEIVER_PUBLIC_KEY_FILE)

        tk.Label(config_frame, text="File CV:").grid(row=5, column=0, sticky="w", pady=2)
        self.cv_file_entry = tk.Entry(config_frame, width=30)
        self.cv_file_entry.grid(row=5, column=1, sticky="ew", pady=2, padx=5)
        select_file_button = tk.Button(config_frame, text="Chọn File", command=self.select_cv_file)
        select_file_button.grid(row=5, column=2, pady=2, padx=5)

        # Nút Gửi
        send_button = tk.Button(parent_frame, text="Gửi CV An toàn", command=self.send_file_gui, height=2, bg="#4CAF50", fg="white", font=("Arial", 12, "bold"))
        send_button.pack(pady=10, padx=10, fill="x")

        # Chat Log Frame
        chat_log_frame = tk.LabelFrame(parent_frame, text="Nhật ký Giao tiếp (Gửi)", padx=10, pady=10)
        chat_log_frame.pack(pady=10, padx=10, fill="both", expand=True)

        self.sender_status_text = scrolledtext.ScrolledText(chat_log_frame, wrap=tk.WORD, width=70, height=15, font=("Courier New", 10))
        self.sender_status_text.pack(fill="both", expand=True)

        self.sender_status_text.tag_config("info", foreground="blue")
        self.sender_status_text.tag_config("warning", foreground="orange")
        self.sender_status_text.tag_config("error", foreground="red")
        self.sender_status_text.tag_config("success", foreground="green")
        self.sender_status_text.tag_config("system", foreground="purple")
        self.sender_status_text.tag_config("sent", foreground="darkgrey")
        self.sender_status_text.tag_config("received", foreground="darkblue")

        clear_log_button = tk.Button(parent_frame, text="Xóa Nhật ký (Gửi)", command=lambda: self.clear_chat_log(self.sender_status_text), bg="#f44336", fg="white", font=("Arial", 10))
        clear_log_button.pack(pady=5, padx=10, anchor="e")

    def update_chat_log_sender(self, text, tag=None):
        self.update_chat_log(self.sender_status_text, text, tag)

    def select_cv_file(self):
        file_path = filedialog.askopenfilename(
            title="Chọn file CV (PDF)",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        if file_path:
            self.cv_file_path = file_path
            self.cv_file_entry.delete(0, tk.END)
            self.cv_file_entry.insert(0, os.path.basename(file_path))
            self.update_chat_log_sender(f"Đã chọn file: {self.cv_file_path}", "info")
        else:
            self.cv_file_path = ''
            self.update_chat_log_sender("Chưa chọn file CV.", "warning")

    def send_file_gui(self):
        receiver_host = self.sender_receiver_host_entry.get()
        receiver_port = int(self.sender_receiver_port_entry.get())
        my_ip = self.sender_my_ip_entry.get()
        sender_private_key_file = self.sender_private_key_entry.get()
        receiver_public_key_file = self.sender_receiver_public_key_entry.get()

        if not hasattr(self, 'cv_file_path') or not self.cv_file_path:
            messagebox.showerror("Lỗi", "Vui lòng chọn file CV trước khi gửi.")
            self.update_chat_log_sender("LỖI: Chưa chọn file CV.", "error")
            return

        if not os.path.exists(self.cv_file_path):
            messagebox.showerror("Lỗi", f"File '{self.cv_file_path}' không tồn tại. Vui lòng kiểm tra lại.")
            self.update_chat_log_sender(f"LỖI: File '{self.cv_file_path}' không tồn tại.", "error")
            return
        
        if not os.path.exists(sender_private_key_file) or not os.path.exists(receiver_public_key_file):
            messagebox.showerror("Lỗi Khóa", f"Không tìm thấy file khóa '{sender_private_key_file}' hoặc '{receiver_public_key_file}'. Vui lòng kiểm tra lại tên file và đường dẫn, hoặc chạy `generate_keys.py`.")
            self.update_chat_log_sender(f"LỖI: Không tìm thấy file khóa '{sender_private_key_file}' hoặc '{receiver_public_key_file}'.", "error")
            return

        self.update_chat_log_sender("\nBắt đầu quá trình gửi CV...", "system")
        threading.Thread(target=self._send_file_logic, args=(
            receiver_host, receiver_port, my_ip, 
            sender_private_key_file, receiver_public_key_file, self.cv_file_path
        )).start()

    def _send_file_logic(self, receiver_host, receiver_port, my_ip, sender_private_key_file, receiver_public_key_file, cv_filename):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect((receiver_host, receiver_port))
                self.update_chat_log_sender(f"Đã kết nối tới server {receiver_host}:{receiver_port}", "success")

                # 1. Handshake
                handshake_message = f"Hello!|{my_ip}"
                s.sendall(handshake_message.encode('utf-8'))
                self.update_chat_log_sender(f"Gửi Handshake: {handshake_message}", "sent")

                response = s.recv(1024).decode('utf-8')
                self.update_chat_log_sender(f"Phản hồi từ Server: {response}", "received")
                if response != "Ready!":
                    self.update_chat_log_sender(f"Server không sẵn sàng. Kết thúc.", "error")
                    messagebox.showerror("Lỗi Handshake", f"Server không sẵn sàng. Phản hồi: {response}")
                    return
                self.update_chat_log_sender("Server đã sẵn sàng.", "success")

            except ConnectionRefusedError:
                self.update_chat_log_sender(f"LỖI: Kết nối tới {receiver_host}:{receiver_port} bị từ chối.", "error")
                self.update_chat_log_sender("Vui lòng đảm bảo server nhận đang chạy và cấu hình IP đúng.", "error")
                messagebox.showerror("Lỗi Kết nối", "Kết nối bị từ chối. Đảm bảo receiver đang chạy và cấu hình IP đúng.")
                return
            except Exception as e:
                self.update_chat_log_sender(f"Đã xảy ra lỗi khi kết nối hoặc handshake: {e}", "error")
                messagebox.showerror("Lỗi", f"Lỗi kết nối/handshake: {e}")
                return

            # 2. Xác thực & Trao đổi khóa
            self.update_chat_log_sender("Bắt đầu quá trình xác thực và mã hóa...", "system")
            session_key = get_random_bytes(16)
            timestamp = int(time.time())
            metadata = f"{os.path.basename(cv_filename)}|{timestamp}|{my_ip}".encode('utf-8')

            try:
                sender_private_key = RSA.import_key(open(sender_private_key_file).read())
                h_metadata = SHA512.new(metadata)
                signature = pkcs1_15.new(sender_private_key).sign(h_metadata)
                self.update_chat_log_sender("Đã tạo chữ ký số cho metadata bằng RSA/SHA-512 (PKCS1_v1.5).", "info")

                receiver_public_key = RSA.import_key(open(receiver_public_key_file).read())
                cipher_rsa = PKCS1_OAEP.new(receiver_public_key, hashAlgo=SHA512)
                encrypted_session_key = cipher_rsa.encrypt(session_key)
                self.update_chat_log_sender("Đã mã hóa Session Key bằng RSA/OAEP (SHA-512).", "info")

            except FileNotFoundError as e:
                self.update_chat_log_sender(f"LỖI: Không tìm thấy file khóa: {e}. Vui lòng kiểm tra lại tên file và đường dẫn.", "error")
                messagebox.showerror("Lỗi Khóa", f"Không tìm thấy file khóa: {e}. Vui lòng kiểm tra lại tên file và đường dẫn, hoặc chạy `generate_keys.py`.")
                return
            except Exception as e:
                self.update_chat_log_sender(f"LỖI: Xảy ra lỗi trong quá trình xác thực/trao đổi khóa: {e}", "error")
                messagebox.showerror("Lỗi Xác thực", f"Lỗi xác thực/trao đổi khóa: {e}")
                return

            # 3. Mã hóa & Kiểm tra toàn vẹn
            try:
                with open(cv_filename, 'rb') as f:
                    file_data = f.read()
            except FileNotFoundError:
                self.update_chat_log_sender(f"LỖI: Không tìm thấy file '{cv_filename}'. Vui lòng kiểm tra lại.", "error")
                messagebox.showerror("Lỗi File", f"Không tìm thấy file '{cv_filename}'.")
                return
            except Exception as e:
                self.update_chat_log_sender(f"LỖI: Không thể đọc file '{cv_filename}': {e}", "error")
                messagebox.showerror("Lỗi File", f"Không thể đọc file '{cv_filename}': {e}")
                return

            iv = get_random_bytes(AES.block_size)
            cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
            ciphertext = cipher_aes.encrypt(pad(file_data, AES.block_size))
            self.update_chat_log_sender(f"Đã mã hóa file CV ({len(file_data)} bytes) bằng AES-CBC.", "info")

            integrity_hash = SHA512.new(iv + ciphertext).hexdigest()
            self.update_chat_log_sender("Đã tính hash toàn vẹn SHA-512(IV || ciphertext).", "info")
            
            payload = {
                "metadata": base64.b64encode(metadata).decode('utf-8'),
                "encrypted_session_key": base64.b64encode(encrypted_session_key).decode('utf-8'),
                "iv": base64.b64encode(iv).decode('utf-8'),
                "cipher": base64.b64encode(ciphertext).decode('utf-8'),
                "hash": integrity_hash,
                "sig": base64.b64encode(signature).decode('utf-8')
            }

            payload_bytes = json.dumps(payload).encode('utf-8')
            payload_size = len(payload_bytes)
            s.sendall(struct.pack('>I', payload_size))
            s.sendall(payload_bytes)
            self.update_chat_log_sender(f"Đã gửi gói tin mã hóa có kích thước {payload_size} bytes tới server.", "sent")

            final_response = s.recv(1024).decode('utf-8')
            self.update_chat_log_sender(f"Phản hồi cuối cùng từ Server: {final_response}", "received")
            if "ACK" in final_response:
                self.update_chat_log_sender("Gửi CV thành công!", "success")
                messagebox.showinfo("Thành công", "Gửi CV thành công!")
            else:
                self.update_chat_log_sender(f"Gửi CV thất bại. Lý do: {final_response}", "error")
                messagebox.showerror("Thất bại", f"Gửi CV thất bại. Lý do: {final_response}")

if __name__ == '__main__':
    root = tk.Tk()
    app = SenderApp(root)
    root.mainloop()
