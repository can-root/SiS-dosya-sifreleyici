import os
import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton, QVBoxLayout,
    QHBoxLayout, QFileDialog, QLabel, QLineEdit, QFrame, QMessageBox
)
from cryptography.fernet import Fernet, InvalidToken

def anahtar_oluştur():
    anahtar = Fernet.generate_key()
    return anahtar.decode()

def dosya_şifrele(girdi_dosyası_yolu, çıktı_dosyası_yolu, anahtar):
    f = Fernet(anahtar.encode())
    with open(girdi_dosyası_yolu, "rb") as dosya:
        dosya_verisi = dosya.read()
    şifrelenmiş_veri = f.encrypt(dosya_verisi)

    with open(çıktı_dosyası_yolu, "wb") as dosya:
        dosya.write(şifrelenmiş_veri)

def dosya_şifresini_çöz(girdi_dosyası_yolu, çıktı_dosyası_yolu, anahtar):
    f = Fernet(anahtar.encode())
    with open(girdi_dosyası_yolu, "rb") as dosya:
        şifrelenmiş_veri = dosya.read()
    çözülen_veri = f.decrypt(şifrelenmiş_veri)

    with open(çıktı_dosyası_yolu, "wb") as dosya:
        dosya.write(çözülen_veri)

class DosyaŞifreleyici(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Dosya Şifreleyici')
        self.setStyleSheet("background-color: #2E2E2E; color: #FFFFFF;")
        self.resize(800, 300)

        self.layout = QVBoxLayout()

        şifreleme_düzeni = QVBoxLayout()
        self.girdi_etiket = QLabel("Şifrelenecek dosyanın yolunu seçin:")
        şifreleme_düzeni.addWidget(self.girdi_etiket)

        self.girdi_yolu = QLineEdit(self)
        self.girdi_yolu.setReadOnly(True)
        şifreleme_düzeni.addWidget(self.girdi_yolu)

        self.gözat_girdi_butonu = QPushButton('Gözat...', self)
        self.gözat_girdi_butonu.clicked.connect(self.browse_input_file)
        şifreleme_düzeni.addWidget(self.gözat_girdi_butonu)

        self.çıktı_etiket = QLabel("Şifreli dosyanın kaydedileceği yolu seçin:")
        şifreleme_düzeni.addWidget(self.çıktı_etiket)

        self.çıktı_yolu = QLineEdit(self)
        self.çıktı_yolu.setReadOnly(True)
        şifreleme_düzeni.addWidget(self.çıktı_yolu)

        self.gözat_çıktı_butonu = QPushButton('Klasör Seç...', self)
        self.gözat_çıktı_butonu.clicked.connect(self.browse_output_folder)
        şifreleme_düzeni.addWidget(self.gözat_çıktı_butonu)

        self.anahtar_etiket = QLabel("Anahtar dosyası yolu:")
        şifreleme_düzeni.addWidget(self.anahtar_etiket)

        self.anahtar_yolu = QLineEdit(self)
        self.anahtar_yolu.setReadOnly(True)
        şifreleme_düzeni.addWidget(self.anahtar_yolu)

        self.gözat_anahtar_butonu = QPushButton('Klasör Seç...', self)
        self.gözat_anahtar_butonu.clicked.connect(self.browse_key_folder)
        şifreleme_düzeni.addWidget(self.gözat_anahtar_butonu)

        self.şifrele_butonu = QPushButton('Dosyayı Şifrele', self)
        self.şifrele_butonu.clicked.connect(self.encrypt_file)
        şifreleme_düzeni.addWidget(self.şifrele_butonu)

        ayırıcı = QFrame()
        ayırıcı.setFrameShape(QFrame.VLine)
        ayırıcı.setFrameShadow(QFrame.Sunken)

        şifre_çözme_düzeni = QVBoxLayout()
        self.şifre_çözme_etiket = QLabel("Şifresi çözülecek dosyanın yolunu seçin:")
        şifre_çözme_düzeni.addWidget(self.şifre_çözme_etiket)

        self.şifre_çözme_girdi_yolu = QLineEdit(self)
        self.şifre_çözme_girdi_yolu.setReadOnly(True)
        şifre_çözme_düzeni.addWidget(self.şifre_çözme_girdi_yolu)

        self.gözat_şifre_çözme_butonu = QPushButton('Gözat...', self)
        self.gözat_şifre_çözme_butonu.clicked.connect(self.browse_decrypt_input_file)
        şifre_çözme_düzeni.addWidget(self.gözat_şifre_çözme_butonu)

        self.şifre_çözme_çıktı_etiket = QLabel("Çözülmüş dosyanın kaydedileceği yolu seçin:")
        şifre_çözme_düzeni.addWidget(self.şifre_çözme_çıktı_etiket)

        self.şifre_çözme_çıktı_yolu = QLineEdit(self)
        self.şifre_çözme_çıktı_yolu.setReadOnly(True)
        şifre_çözme_düzeni.addWidget(self.şifre_çözme_çıktı_yolu)

        self.gözat_şifre_çözme_butonu = QPushButton('Klasör Seç...', self)
        self.gözat_şifre_çözme_butonu.clicked.connect(self.browse_decrypt_folder)
        şifre_çözme_düzeni.addWidget(self.gözat_şifre_çözme_butonu)

        self.anahtar_etiket_şifre_çözme = QLabel("Anahtar dosyasının yolunu seçin:")
        şifre_çözme_düzeni.addWidget(self.anahtar_etiket_şifre_çözme)

        self.anahtar_yolu_şifre_çözme = QLineEdit(self)
        self.anahtar_yolu_şifre_çözme.setReadOnly(True)
        şifre_çözme_düzeni.addWidget(self.anahtar_yolu_şifre_çözme)

        self.gözat_anahtar_butonu_şifre_çözme = QPushButton('Gözat...', self)
        self.gözat_anahtar_butonu_şifre_çözme.clicked.connect(self.browse_key_file_decrypt)
        şifre_çözme_düzeni.addWidget(self.gözat_anahtar_butonu_şifre_çözme)

        self.şifre_çöz_butonu = QPushButton('Dosyanın Şifresini Çöz', self)
        self.şifre_çöz_butonu.clicked.connect(self.decrypt_file)
        şifre_çözme_düzeni.addWidget(self.şifre_çöz_butonu)

        ana_düzen = QHBoxLayout()
        ana_düzen.addLayout(şifreleme_düzeni)
        ana_düzen.addWidget(ayırıcı)
        ana_düzen.addLayout(şifre_çözme_düzeni)

        self.layout.addLayout(ana_düzen)
        self.setLayout(self.layout)

    def mesaj_göster(self, başlık, mesaj):
        msg = QMessageBox()
        msg.setWindowTitle(başlık)
        msg.setText(mesaj)
        msg.exec_()

    def browse_input_file(self):
        dosya_adi, _ = QFileDialog.getOpenFileName(self, 'Dosya Seç')
        if dosya_adi:
            self.girdi_yolu.setText(dosya_adi)

    def browse_output_folder(self):
        klasör = QFileDialog.getExistingDirectory(self, 'Klasör Seç')
        if klasör:
            orijinal_uzantı = os.path.splitext(self.girdi_yolu.text())[1]
            çıktı_dosyası_adi = os.path.join(klasör, f"şifreli_dosya{orijinal_uzantı}.enc")
            self.çıktı_yolu.setText(çıktı_dosyası_adi)

    def browse_key_folder(self):
        klasör = QFileDialog.getExistingDirectory(self, 'Klasör Seç')
        if klasör:
            anahtar_dosyası_adi = os.path.join(klasör, "anahtar.txt")
            self.anahtar_yolu.setText(anahtar_dosyası_adi)

    def browse_decrypt_input_file(self):
        dosya_adi, _ = QFileDialog.getOpenFileName(self, 'Şifresi Çözülecek Dosyayı Seç')
        if dosya_adi:
            self.şifre_çözme_girdi_yolu.setText(dosya_adi)

    def browse_decrypt_folder(self):
        klasör = QFileDialog.getExistingDirectory(self, 'Klasör Seç')
        if klasör:
            çıktı_dosyası_adi = os.path.join(klasör, "çözülmüş_dosya" + os.path.splitext(self.şifre_çözme_girdi_yolu.text())[1])
            self.şifre_çözme_çıktı_yolu.setText(çıktı_dosyası_adi)

    def browse_key_file_decrypt(self):
        dosya_adi, _ = QFileDialog.getOpenFileName(self, 'Anahtar Dosyasını Seç')
        if dosya_adi:
            self.anahtar_yolu_şifre_çözme.setText(dosya_adi)

    def encrypt_file(self):
        girdi_dosyası_yolu = self.girdi_yolu.text()
        çıktı_dosyası_yolu = self.çıktı_yolu.text()
        anahtar_dosyası_yolu = self.anahtar_yolu.text()

        if not girdi_dosyası_yolu or not çıktı_dosyası_yolu or not anahtar_dosyası_yolu:
            self.mesaj_göster("Hata", "Lütfen tüm dosya yollarını doldurun.")
            return

        try:
            anahtar = anahtar_oluştur()
            dosya_şifrele(girdi_dosyası_yolu, çıktı_dosyası_yolu, anahtar)

            with open(anahtar_dosyası_yolu, "w") as anahtar_dosyası:
                anahtar_dosyası.write(anahtar)

            self.mesaj_göster("Başarılı", "Dosya başarıyla şifrelendi.")
        except Exception:
            self.mesaj_göster("Hata", "Şifreleme hatası.")

    def decrypt_file(self):
        girdi_dosyası_yolu = self.şifre_çözme_girdi_yolu.text()
        çıktı_dosyası_yolu = self.şifre_çözme_çıktı_yolu.text()
        anahtar_dosyası_yolu = self.anahtar_yolu_şifre_çözme.text()

        if not girdi_dosyası_yolu or not çıktı_dosyası_yolu or not anahtar_dosyası_yolu:
            self.mesaj_göster("Hata", "Lütfen tüm dosya yollarını doldurun.")
            return

        try:
            with open(anahtar_dosyası_yolu, "r") as anahtar_dosyası:
                anahtar = anahtar_dosyası.read()

            dosya_şifresini_çöz(girdi_dosyası_yolu, çıktı_dosyası_yolu, anahtar)
            self.mesaj_göster("Başarılı", "Dosyanın şifresi başarıyla çözüldü.")
        except InvalidToken:
            self.mesaj_göster("Hata", "Geçersiz anahtar! Dosya çözülemedi.")
        except Exception:
            self.mesaj_göster("Hata", "Şifre çözme hatası.")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = DosyaŞifreleyici()
    ex.show()
    sys.exit(app.exec_())
