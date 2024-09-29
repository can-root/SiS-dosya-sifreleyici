import os
import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton, QVBoxLayout,
    QHBoxLayout, QFileDialog, QLabel, QLineEdit, QFrame, QMessageBox
)
from cryptography.fernet import Fernet, InvalidToken

# 256 bitlik anahtar oluşturma
def generate_key():
    key = Fernet.generate_key()
    return key.decode()  # Anahtarı string olarak döndür

# Dosyayı şifreleme
def encrypt_file(input_filepath, output_filepath, key):
    f = Fernet(key.encode())
    with open(input_filepath, "rb") as file:
        file_data = file.read()
    encrypted_data = f.encrypt(file_data)

    with open(output_filepath, "wb") as file:
        file.write(encrypted_data)

# Dosyayı şifre çözme
def decrypt_file(input_filepath, output_filepath, key):
    f = Fernet(key.encode())
    with open(input_filepath, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = f.decrypt(encrypted_data)

    with open(output_filepath, "wb") as file:
        file.write(decrypted_data)

class FileEncryptor(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Dosya Şifreleyici')
        self.setStyleSheet("background-color: #2E2E2E; color: #FFFFFF;")  # Karanlık tema
        self.resize(800, 300)  # Genişlik 800

        self.layout = QVBoxLayout()

        # Şifreleme kısmı
        encrypt_layout = QVBoxLayout()
        self.input_label = QLabel("Şifrelenecek dosyanın yolunu seçin:")
        encrypt_layout.addWidget(self.input_label)

        self.input_path = QLineEdit(self)
        self.input_path.setReadOnly(True)  # Sadece okunabilir yap
        encrypt_layout.addWidget(self.input_path)

        self.browse_input_button = QPushButton('Gözat...', self)
        self.browse_input_button.clicked.connect(self.browse_input_file)
        encrypt_layout.addWidget(self.browse_input_button)

        self.output_label = QLabel("Şifreli dosyanın kaydedileceği yolu seçin:")
        encrypt_layout.addWidget(self.output_label)

        self.output_path = QLineEdit(self)
        self.output_path.setReadOnly(True)  # Sadece okunabilir yap
        encrypt_layout.addWidget(self.output_path)

        self.browse_output_button = QPushButton('Klasör Seç...', self)
        self.browse_output_button.clicked.connect(self.browse_output_folder)
        encrypt_layout.addWidget(self.browse_output_button)

        self.key_label = QLabel("Anahtar dosyası yolu:")
        encrypt_layout.addWidget(self.key_label)

        self.key_path = QLineEdit(self)
        self.key_path.setReadOnly(True)  # Sadece okunabilir yap
        encrypt_layout.addWidget(self.key_path)

        self.browse_key_button = QPushButton('Klasör Seç...', self)
        self.browse_key_button.clicked.connect(self.browse_key_folder)
        encrypt_layout.addWidget(self.browse_key_button)

        self.encrypt_button = QPushButton('Dosyayı Şifrele', self)
        self.encrypt_button.clicked.connect(self.encrypt_file)
        encrypt_layout.addWidget(self.encrypt_button)

        # Çizgi
        line = QFrame()
        line.setFrameShape(QFrame.VLine)
        line.setFrameShadow(QFrame.Sunken)

        # Şifre çözme kısmı
        decrypt_layout = QVBoxLayout()
        self.decrypt_label = QLabel("Şifresi çözülecek dosyanın yolunu seçin:")
        decrypt_layout.addWidget(self.decrypt_label)

        self.decrypt_input_path = QLineEdit(self)
        self.decrypt_input_path.setReadOnly(True)  # Sadece okunabilir yap
        decrypt_layout.addWidget(self.decrypt_input_path)

        self.browse_decrypt_input_button = QPushButton('Gözat...', self)
        self.browse_decrypt_input_button.clicked.connect(self.browse_decrypt_input_file)
        decrypt_layout.addWidget(self.browse_decrypt_input_button)

        self.decrypt_output_label = QLabel("Çözülmüş dosyanın kaydedileceği yolu seçin:")
        decrypt_layout.addWidget(self.decrypt_output_label)

        self.decrypt_output_path = QLineEdit(self)
        self.decrypt_output_path.setReadOnly(True)  # Sadece okunabilir yap
        decrypt_layout.addWidget(self.decrypt_output_path)

        self.browse_decrypt_output_button = QPushButton('Klasör Seç...', self)
        self.browse_decrypt_output_button.clicked.connect(self.browse_decrypt_folder)
        decrypt_layout.addWidget(self.browse_decrypt_output_button)

        self.key_label_decrypt = QLabel("Anahtar dosyasının yolunu seçin:")
        decrypt_layout.addWidget(self.key_label_decrypt)

        self.key_path_decrypt = QLineEdit(self)
        self.key_path_decrypt.setReadOnly(True)  # Sadece okunabilir yap
        decrypt_layout.addWidget(self.key_path_decrypt)

        self.browse_key_button_decrypt = QPushButton('Gözat...', self)
        self.browse_key_button_decrypt.clicked.connect(self.browse_key_file_decrypt)
        decrypt_layout.addWidget(self.browse_key_button_decrypt)

        self.decrypt_button = QPushButton('Dosyanın Şifresini Çöz', self)
        self.decrypt_button.clicked.connect(self.decrypt_file)
        decrypt_layout.addWidget(self.decrypt_button)

        # Ana düzen
        main_layout = QHBoxLayout()
        main_layout.addLayout(encrypt_layout)
        main_layout.addWidget(line)
        main_layout.addLayout(decrypt_layout)

        self.layout.addLayout(main_layout)
        self.setLayout(self.layout)

    def show_message(self, title, message):
        msg = QMessageBox()
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.exec_()

    def browse_input_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, 'Dosya Seç')
        if filename:
            self.input_path.setText(filename)

    def browse_output_folder(self):
        folder = QFileDialog.getExistingDirectory(self, 'Klasör Seç')
        if folder:
            original_ext = os.path.splitext(self.input_path.text())[1]  # Orijinal uzantıyı al
            output_filename = os.path.join(folder, f"şifreli_dosya{original_ext}.enc")  # Varsayılan dosya adı
            self.output_path.setText(output_filename)

    def browse_key_folder(self):
        folder = QFileDialog.getExistingDirectory(self, 'Klasör Seç')
        if folder:
            key_filename = os.path.join(folder, "anahtar.txt")  # Varsayılan anahtar dosyası adı
            self.key_path.setText(key_filename)

    def browse_decrypt_input_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, 'Şifresi Çözülecek Dosyayı Seç')
        if filename:
            self.decrypt_input_path.setText(filename)

    def browse_decrypt_folder(self):
        folder = QFileDialog.getExistingDirectory(self, 'Klasör Seç')
        if folder:
            output_filename = os.path.join(folder, "çözülmüş_dosya" + os.path.splitext(self.decrypt_input_path.text())[1])  # Orijinal uzantıyı koru
            self.decrypt_output_path.setText(output_filename)

    def browse_key_file_decrypt(self):
        filename, _ = QFileDialog.getOpenFileName(self, 'Anahtar Dosyasını Seç')
        if filename:
            self.key_path_decrypt.setText(filename)

    def encrypt_file(self):
        input_filepath = self.input_path.text()
        output_filepath = self.output_path.text()
        key_filepath = self.key_path.text()

        if not input_filepath or not output_filepath or not key_filepath:
            self.show_message("Hata", "Lütfen tüm dosya yollarını doldurun.")
            return

        try:
            key = generate_key()
            encrypt_file(input_filepath, output_filepath, key)

            with open(key_filepath, "w") as key_file:
                key_file.write(key)

            self.show_message("Başarılı", "Dosya başarıyla şifrelendi.")
        except Exception:
            self.show_message("Hata", "Şifreleme hatası.")

    def decrypt_file(self):
        input_filepath = self.decrypt_input_path.text()
        output_filepath = self.decrypt_output_path.text()
        key_filepath = self.key_path_decrypt.text()

        if not input_filepath or not output_filepath or not key_filepath:
            self.show_message("Hata", "Lütfen tüm dosya yollarını doldurun.")
            return

        try:
            with open(key_filepath, "r") as key_file:
                key = key_file.read()

            decrypt_file(input_filepath, output_filepath, key)
            self.show_message("Başarılı", "Dosyanın şifresi başarıyla çözüldü.")
        except InvalidToken:
            self.show_message("Hata", "Geçersiz anahtar! Dosya çözülemedi.")
        except Exception:
            self.show_message("Hata", "Şifre çözme hatası.")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = FileEncryptor()
    ex.show()
    sys.exit(app.exec_())
