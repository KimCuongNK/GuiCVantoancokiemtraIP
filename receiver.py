# receiver.py
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import socket
import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Util.Padding import unpad
import struct
import os
import threading
import time
from datetime import datetime
import shutil # Thêm thư viện shutil để sao chép file

# --- Configuration Defaults ---
DEFAULT_HOST = '0.0.0.0' # Listen on all network interfaces
DEFAULT_PORT = 65432 # If you encounter 'WinError 10013', try changing this port (e.g., 65433, 65434)
DEFAULT_ALLOWED_IPS = '127.0.0.1' # Comma-separated IPs
DEFAULT_RECEIVER_PRIVATE_KEY_FILE = 'receiver1_private.pem'
DEFAULT_SENDER_PUBLIC_KEY_FILE = 'sender1_public.pem'

class ReceiverApp:
    def __init__(self, master):
        self.master = master
        master.title("Ứng dụng Server Nhận CV An toàn")
        master.geometry("750x800")
        master.resizable(False, False)

        self.server_socket = None
        self.server_thread = None
        self.running = False

        self.create_widgets()
        self.update_chat_log("Server đã sẵn sàng cấu hình.", "info")

        # Xử lý đóng cửa sổ
        master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        if self.running:
            if messagebox.askokcancel("Thoát", "Server đang chạy. Bạn có muốn dừng server và thoát ứng dụng không?"):
                self.stop_server()
                self.master.destroy()
        else:
            self.master.destroy()

    def create_widgets(self):
        # Configuration Frame
        config_frame = tk.LabelFrame(self.master, text="Cấu hình Server", padx=10, pady=10)
        config_frame.pack(pady=10, padx=10, fill="x")

        tk.Label(config_frame, text="Host:").grid(row=0, column=0, sticky="w", pady=2)
        self.host_entry = tk.Entry(config_frame, width=40)
        self.host_entry.grid(row=0, column=1, pady=2, padx=5)
        self.host_entry.insert(0, DEFAULT_HOST)

        tk.Label(config_frame, text="Port:").grid(row=1, column=0, sticky="w", pady=2)
        self.port_entry = tk.Entry(config_frame, width=40)
        self.port_entry.grid(row=1, column=1, pady=2, padx=5)
        self.port_entry.insert(0, DEFAULT_PORT)

        tk.Label(config_frame, text="IP được phép (cách nhau bởi dấu phẩy):").grid(row=2, column=0, sticky="w", pady=2)
        self.allowed_ips_entry = tk.Entry(config_frame, width=40)
        self.allowed_ips_entry.grid(row=2, column=1, pady=2, padx=5)
        self.allowed_ips_entry.insert(0, DEFAULT_ALLOWED_IPS)

        tk.Label(config_frame, text="Khóa riêng tư Người nhận:").grid(row=3, column=0, sticky="w", pady=2)
        self.receiver_private_key_entry = tk.Entry(config_frame, width=40)
        self.receiver_private_key_entry.grid(row=3, column=1, pady=2, padx=5)
        self.receiver_private_key_entry.insert(0, DEFAULT_RECEIVER_PRIVATE_KEY_FILE)

        tk.Label(config_frame, text="Khóa công khai Người gửi:").grid(row=4, column=0, sticky="w", pady=2)
        self.sender_public_key_entry = tk.Entry(config_frame, width=40)
        self.sender_public_key_entry.grid(row=4, column=1, pady=2, padx=5)
        self.sender_public_key_entry.insert(0, DEFAULT_SENDER_PUBLIC_KEY_FILE)

        # Control Buttons Frame
        control_frame = tk.Frame(self.master, padx=10, pady=5)
        control_frame.pack(pady=5, padx=10, fill="x")

        self.start_button = tk.Button(control_frame, text="Bắt đầu Server", command=self.start_server, bg="#4CAF50", fg="white", font=("Arial", 12, "bold"))
        self.start_button.pack(side=tk.LEFT, expand=True, fill="x", padx=5)

        self.stop_button = tk.Button(control_frame, text="Dừng Server", command=self.stop_server, bg="#f44336", fg="white", font=("Arial", 12, "bold"), state=tk.DISABLED)
        self.stop_button.pack(side=tk.RIGHT, expand=True, fill="x", padx=5)

        # Chat Log Frame
        chat_log_frame = tk.LabelFrame(self.master, text="Nhật ký Giao tiếp", padx=10, pady=10)
        chat_log_frame.pack(pady=10, padx=10, fill="both", expand=True)

        self.status_text = scrolledtext.ScrolledText(chat_log_frame, wrap=tk.WORD, width=70, height=15, font=("Courier New", 10))
        self.status_text.pack(fill="both", expand=True)

        # Tags for colored messages
        self.status_text.tag_config("info", foreground="blue")
        self.status_text.tag_config("warning", foreground="orange")
        self.status_text.tag_config("error", foreground="red")
        self.status_text.tag_config("success", foreground="green")
        self.status_text.tag_config("system", foreground="purple")
        self.status_text.tag_config("received", foreground="darkblue") # For received messages/data
        self.status_text.tag_config("sent", foreground="darkgrey") # For sent acknowledgments

        # Clear Log Button
        clear_log_button = tk.Button(self.master, text="Xóa Nhật ký", command=self.clear_chat_log, bg="#f44336", fg="white", font=("Arial", 10))
        clear_log_button.pack(pady=5, padx=10, anchor="e")

        # Received Files Frame
        received_files_frame = tk.LabelFrame(self.master, text="File Đã Nhận", padx=10, pady=10)
        received_files_frame.pack(pady=10, padx=10, fill="x")

        self.received_files_listbox = tk.Listbox(received_files_frame, height=5, font=("Arial", 10))
        self.received_files_listbox.pack(side=tk.LEFT, fill="both", expand=True)
        
        # Add a scrollbar to the listbox
        listbox_scrollbar = tk.Scrollbar(received_files_frame, orient="vertical", command=self.received_files_listbox.yview)
        listbox_scrollbar.pack(side=tk.RIGHT, fill="y")
        self.received_files_listbox.config(yscrollcommand=listbox_scrollbar.set)

        # Download Button
        download_button = tk.Button(received_files_frame, text="Tải File Đã Chọn", command=self.download_selected_file, bg="#007BFF", fg="white", font=("Arial", 10))
        download_button.pack(pady=5, padx=5, fill="x")


    def update_chat_log(self, text, tag=None):
        """
        Updates the scrolled text box (chat log) and prints to console.
        This method is thread-safe.
        """
        current_time = datetime.now().strftime("[%H:%M:%S]")
        self.master.after(0, lambda: self._insert_log_text(f"{current_time} {text}\n", tag))

    def _insert_log_text(self, text, tag):
        self.status_text.insert(tk.END, text, tag)
        self.status_text.see(tk.END)

    def clear_chat_log(self):
        """
        Clears the content of the chat log text box.
        """
        self.status_text.delete(1.0, tk.END)
        self.update_chat_log("Nhật ký đã được xóa.", "info")

    def update_received_files_list(self, filename):
        """
        Adds a filename to the received files listbox.
        This method is thread-safe.
        """
        self.master.after(0, lambda: self.received_files_listbox.insert(tk.END, filename))

    def download_selected_file(self):
        """
        Allows the user to download the selected file from the received files list.
        """
        selected_indices = self.received_files_listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("Không có file nào được chọn", "Vui lòng chọn một file từ danh sách để tải về.")
            self.update_chat_log("Không có file nào được chọn để tải về.", "warning")
            return

        selected_filename_in_list = self.received_files_listbox.get(selected_indices[0])
        # The actual saved file name is prefixed with "received_"
        source_file_path = os.path.join(os.getcwd(), selected_filename_in_list)

        if not os.path.exists(source_file_path):
            messagebox.showerror("Lỗi", f"File '{selected_filename_in_list}' không tồn tại trong thư mục hiện tại.")
            self.update_chat_log(f"LỖI: File '{selected_filename_in_list}' không tồn tại để tải về.", "error")
            return

        # Open a save as dialog
        initial_filename = selected_filename_in_list.replace("received_", "") # Remove "received_" prefix for suggested name
        save_path = filedialog.asksaveasfilename(
            defaultextension=".pdf", # Assuming CVs are PDFs
            initialfile=initial_filename,
            title="Lưu file CV đã nhận",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
        )

        if save_path:
            try:
                shutil.copy(source_file_path, save_path)
                messagebox.showinfo("Thành công", f"Đã tải file '{selected_filename_in_list}' về: {save_path}")
                self.update_chat_log(f"Đã tải file '{selected_filename_in_list}' về: {save_path}", "success")
            except Exception as e:
                messagebox.showerror("Lỗi Tải về", f"Không thể tải file về: {e}")
                self.update_chat_log(f"LỖI: Không thể tải file '{selected_filename_in_list}' về: {e}", "error")
        else:
            self.update_chat_log("Hủy tải file.", "info")

    def start_server(self):
        if self.running:
            self.update_chat_log("Server đã chạy rồi.", "warning")
            return

        try:
            self.host = self.host_entry.get()
            self.port = int(self.port_entry.get())
            self.allowed_ips = [ip.strip() for ip in self.allowed_ips_entry.get().split(',') if ip.strip()]
            self.receiver_private_key_file = self.receiver_private_key_entry.get()
            self.sender_public_key_file = self.sender_public_key_entry.get()

            # Basic validation for key files
            if not os.path.exists(self.receiver_private_key_file):
                messagebox.showerror("Lỗi", f"File khóa riêng tư người nhận không tồn tại: {self.receiver_private_key_file}")
                self.update_chat_log(f"LỖI: File khóa riêng tư người nhận không tồn tại: {self.receiver_private_key_file}", "error")
                return
            if not os.path.exists(self.sender_public_key_file):
                messagebox.showerror("Lỗi", f"File khóa công khai người gửi không tồn tại: {self.sender_public_key_file}")
                self.update_chat_log(f"LỖI: File khóa công khai người gửi không tồn tại: {self.sender_public_key_file}", "error")
                return

            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow reuse of address
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen()
            
            self.running = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.update_chat_log(f"Server đang lắng nghe trên {self.host}:{self.port}...", "success")

            self.server_thread = threading.Thread(target=self.listen_for_connections)
            self.server_thread.daemon = True # Allow main program to exit even if thread is running
            self.server_thread.start()

        except ValueError:
            messagebox.showerror("Lỗi Cấu hình", "Port phải là một số nguyên hợp lệ.")
            self.update_chat_log("LỖI: Port phải là một số nguyên hợp lệ.", "error")
        except socket.error as e:
            # Enhanced error message for WinError 10013
            error_message = f"Không thể khởi động server: {e}\n"
            if "10013" in str(e):
                error_message += "Có vẻ như cổng này đang bị sử dụng bởi một ứng dụng khác hoặc bạn không có quyền truy cập.\nVui lòng thử một cổng khác (ví dụ: 65433, 65434) hoặc chạy ứng dụng với quyền quản trị."
            else:
                error_message += "Kiểm tra xem port có đang bị sử dụng không."
            messagebox.showerror("Lỗi Socket", error_message)
            self.update_chat_log(f"LỖI: {error_message}", "error")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Đã xảy ra lỗi không mong muốn: {e}")
            self.update_chat_log(f"LỖI: Đã xảy ra lỗi không mong muốn: {e}", "error")

    def stop_server(self):
        if not self.running:
            self.update_chat_log("Server chưa chạy.", "warning")
            return

        self.running = False
        if self.server_socket:
            try:
                # To unblock the accept() call, try to connect to the server itself
                # This will cause accept() to return, and the loop will check self.running
                socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((self.host, self.port))
                self.server_socket.shutdown(socket.SHUT_RDWR)
                self.server_socket.close()
                self.update_chat_log("Đang dừng server...", "system")
            except Exception as e:
                self.update_chat_log(f"LỖI khi đóng socket server: {e}", "error")
        
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=1) # Give thread a moment to finish

        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.update_chat_log("Server đã dừng.", "system")

    def listen_for_connections(self):
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                if not self.running: # Check again in case server was stopped during accept()
                    conn.close()
                    break
                self.update_chat_log(f"\n--- Có kết nối mới từ {addr} ---", "system")
                # Handle each connection in a new thread to allow multiple clients
                client_handler = threading.Thread(
                    target=self.handle_connection, # Call the method within the class
                    args=(conn, addr, self.allowed_ips, 
                          self.receiver_private_key_file, self.sender_public_key_file, 
                          self.update_chat_log, self.update_received_files_list)
                )
                client_handler.daemon = True
                client_handler.start()
            except socket.timeout:
                continue # Just re-check self.running
            except OSError as e:
                if self.running: # Only log error if server is supposed to be running
                    self.update_chat_log(f"LỖI khi chấp nhận kết nối: {e}", "error")
                break # Exit loop if socket is closed
            except Exception as e:
                self.update_chat_log(f"LỖI không mong muốn trong luồng lắng nghe: {e}", "error")
                break # Exit loop on unexpected errors

    def handle_connection(self, conn, addr, allowed_ips, receiver_private_key_file, sender_public_key_file, update_chat_log, update_received_files_list):
        """
        Handles a single client connection.
        """
        client_ip = addr[0]
        try:
            # 1. Handshake
            handshake_data = conn.recv(1024).decode('utf-8')
            update_chat_log(f"Nhận được Handshake: {handshake_data}", "received")
            
            parts = handshake_data.split('|')
            if len(parts) != 2 or parts[0] != "Hello!":
                conn.sendall(b"NACK: Invalid Handshake. Expected 'Hello!|Your_IP'")
                update_chat_log("LỖI: Handshake không hợp lệ. Đã gửi NACK.", "error")
                return

            sender_ip_in_handshake = parts[1]
            
            if client_ip not in allowed_ips or sender_ip_in_handshake not in allowed_ips:
                update_chat_log(f"IP không được phép: Client IP={client_ip}, Handshake IP={sender_ip_in_handshake}. Từ chối kết nối.", "error")
                conn.sendall(b"NACK: IP not allowed")
                return
            
            update_chat_log(f"IP {client_ip} hợp lệ. Gửi 'Ready!'.", "success")
            conn.sendall(b"Ready!")
            update_chat_log("Đã gửi 'Ready!'", "sent")

            # 4. Receive and process the main payload
            payload_size_bytes = conn.recv(4)
            if not payload_size_bytes:
                update_chat_log("Lỗi: Kết nối đóng sớm, không nhận được kích thước gói tin.", "error")
                return
            
            payload_size = struct.unpack('>I', payload_size_bytes)[0]
            update_chat_log(f"Sẽ nhận gói tin có kích thước: {payload_size} bytes.", "info")

            full_payload_bytes = b""
            bytes_received = 0
            while bytes_received < payload_size:
                chunk = conn.recv(min(4096, payload_size - bytes_received))
                if not chunk:
                    update_chat_log("Lỗi: Kết nối đóng sớm khi đang nhận dữ liệu.", "error")
                    return
                full_payload_bytes += chunk
                bytes_received += len(chunk)

            update_chat_log("Đã nhận được toàn bộ gói tin chính.", "received")
            
            payload = json.loads(full_payload_bytes.decode('utf-8'))
            
            metadata_encoded = payload['metadata']
            encrypted_session_key_encoded = payload['encrypted_session_key']
            iv_encoded = payload['iv']
            ciphertext_encoded = payload['cipher']
            received_hash = payload['hash']
            signature_encoded = payload['sig']

            metadata = base64.b64decode(metadata_encoded)
            encrypted_session_key = base64.b64decode(encrypted_session_key_encoded)
            iv = base64.b64decode(iv_encoded)
            ciphertext = base64.b64decode(ciphertext_encoded)
            signature = base64.b64decode(signature_encoded)

            # --- INTEGRITY, AUTHENTICATION, AND IP CHECKS ---
            # 4.1 Integrity Check (Hash)
            calculated_hash = SHA512.new(iv + ciphertext).hexdigest()
            if calculated_hash != received_hash:
                error_msg = "NACK: Integrity check failed (hash mismatch)"
                update_chat_log(f"LỖI: {error_msg}. Hash nhận được: {received_hash}, Hash tính toán: {calculated_hash}", "error")
                conn.sendall(error_msg.encode('utf-8'))
                return
            update_chat_log("=> KIỂM TRA HASH: Thành công (SHA-512).", "success")

            # 4.2 Signature Check (Authentication)
            # Đảm bảo file khóa tồn tại trước khi mở
            if not os.path.exists(sender_public_key_file):
                error_msg = f"NACK: File khóa công khai người gửi không tồn tại: {sender_public_key_file}"
                update_chat_log(f"LỖI: {error_msg}", "error")
                conn.sendall(error_msg.encode('utf-8'))
                return

            sender_public_key = RSA.import_key(open(sender_public_key_file).read())
            h_metadata = SHA512.new(metadata)
            try:
                pkcs1_15.new(sender_public_key).verify(h_metadata, signature)
                update_chat_log("=> KIỂM TRA CHỮ KÝ: Thành công (RSA/SHA-512).", "success")
            except (ValueError, TypeError) as e:
                error_msg = f"NACK: Authentication failed (Invalid Signature: {e})"
                update_chat_log(f"LỖI: {error_msg}", "error")
                conn.sendall(error_msg.encode('utf-8'))
                return

            # 4.3 IP check in metadata
            try:
                meta_filename, meta_timestamp, meta_ip = metadata.decode('utf-8').split('|')
            except ValueError:
                error_msg = "NACK: Invalid metadata format"
                update_chat_log(f"LỖỖI: {error_msg}", "error")
                conn.sendall(error_msg.encode('utf-8'))
                return

            if meta_ip != client_ip:
                error_msg = f"NACK: Authentication failed (IP mismatch: Metadata IP={meta_ip} vs Client IP={client_ip})"
                update_chat_log(f"LỖI: {error_msg}", "error")
                conn.sendall(error_msg.encode('utf-8'))
                return
            update_chat_log(f"=> KIỂM TRA IP: Thành công ({meta_ip}).", "success")
            
            # --- If all checks pass, proceed with decryption ---
            update_chat_log("\nTất cả kiểm tra hợp lệ. Bắt đầu giải mã...", "system")
            
            # Đảm bảo file khóa tồn tại trước khi mở
            if not os.path.exists(receiver_private_key_file):
                error_msg = f"NACK: File khóa riêng tư người nhận không tồn tại: {receiver_private_key_file}"
                update_chat_log(f"LỖI: {error_msg}", "error")
                conn.sendall(error_msg.encode('utf-8'))
                return

            receiver_private_key = RSA.import_key(open(receiver_private_key_file).read())
            cipher_rsa = PKCS1_OAEP.new(receiver_private_key, hashAlgo=SHA512)
            session_key = cipher_rsa.decrypt(encrypted_session_key)
            update_chat_log("Đã giải mã thành công Session Key.", "info")

            cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)
            update_chat_log("Đã giải mã thành công file CV.", "info")

            saved_filename = f"received_{meta_filename}"
            with open(saved_filename, 'wb') as f:
                f.write(decrypted_data)
            update_chat_log(f"Đã lưu file vào '{saved_filename}'.", "success")
            update_received_files_list(saved_filename)

            conn.sendall(b"ACK: CV received and verified successfully.")
            update_chat_log("Đã gửi ACK tới người gửi.", "sent")

        except json.JSONDecodeError:
            update_chat_log("Lỗi: Dữ liệu nhận được không phải là JSON hợp lệ.", "error")
            conn.sendall(b"NACK: Invalid JSON payload")
        except Exception as e:
            update_chat_log(f"Đã xảy ra lỗi không mong muốn trong quá trình xử lý kết nối: {e}", "error")
            conn.sendall(f"NACK: An unexpected error occurred: {e}".encode('utf-8'))
        finally:
            update_chat_log(f"--- Đóng kết nối từ {addr} ---", "system")
            conn.close()

if __name__ == '__main__':
    root = tk.Tk()
    app = ReceiverApp(root)
    root.mainloop()
