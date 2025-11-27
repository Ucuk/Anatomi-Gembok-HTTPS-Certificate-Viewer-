# 🔐 Certificate Viewer - GUI
**Kelompok 5 – Proyek Anatomi Gembok HTTPS (PKI & X.509 Certificate Viewer)**  
Mata Kuliah: **Kriptografi**  
Tahun: **2025**

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python)
![GUI](https://img.shields.io/badge/GUI-Tkinter-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 📌 Deskripsi Proyek
Certificate Viewer adalah aplikasi berbasis GUI yang digunakan untuk **mengambil dan menganalisis Sertifikat Digital X.509** dari sebuah domain HTTPS.  
Aplikasi ini dibuat untuk memahami cara kerja:

- **HTTPS / TLS**
- **Public Key Infrastructure (PKI)**
- **Sertifikat Digital X.509**
- **Identitas server dan verifikasi CA**

Aplikasi dikembangkan menggunakan **Python**, **Tkinter**, dan **Cryptography**.

---

# 🧾 **Fungsi Aplikasi**

Aplikasi ini memiliki beberapa fungsi utama sesuai dengan spesifikasi tugas kelompok 5:

### 1️⃣ **Menerima Input Domain**
Pengguna memasukkan nama domain seperti:  
`www.google.com`, `unm.ac.id`, `expired.badssl.com`, dll.

### 2️⃣ **Mengambil Sertifikat Digital X.509**
Aplikasi membuat koneksi HTTPS (port 443) menggunakan SSL/TLS, kemudian mengunduh sertifikat digital milik server.

Proses ini dilakukan menggunakan:
ssl.SSLContext().wrap_socket(..., server_hostname=domain)

markdown
Salin kode

### 3️⃣ **Menganalisis (Parse) Sertifikat**
Aplikasi memproses sertifikat dan menampilkan informasi lengkap:

- **Subject** → pemilik sertifikat (CN, O, L, ST, C)
- **Issuer** → Certificate Authority (CA) penerbit
- **Masa Berlaku** → Valid From, Valid To
- **Status Sertifikat** → VALID / EXPIRED
- **Algoritma Tanda Tangan** → contoh: `sha256WithRSAEncryption`
- **Informasi Kunci Publik**
  - RSA (1024 / 2048 / 4096 bit)
  - ECC (Elliptic Curve seperti `secp256r1`)
  - DSA (jika ada)
- **Fingerprint**
  - SHA-256
  - SHA-1
- **Subject Alternative Names (SAN)**
  Daftar domain lain yang valid untuk sertifikat tersebut.
- **Extensions**
  - basicConstraints  
  - keyUsage  
  - extendedKeyUsage  
  - authorityKeyIdentifier  
  - subjectKeyIdentifier  
  - certificatePolicies  
  - dan lainnya

### 4️⃣ **Menyimpan Sertifikat dalam Format PEM**
Sertifikat dapat disimpan sebagai file `.pem` untuk analisis lanjutan.

### 5️⃣ **Export Informasi ke Format JSON**
Data sertifikat dapat diekspor ke file `.json`.

### 6️⃣ **Batch Mode**
Kamu dapat memasukkan file `.txt` yang berisi daftar domain → aplikasi akan mengekspor hasil analisis semuanya sekaligus.

---

# 📘 **Panduan Penggunaan Aplikasi**

Berikut cara menggunakan Certificate Viewer GUI.
## 🟦 1. Install Dependensi
Pastikan Python 3.8+ terpasang.

Install library:
pip install cryptography

---

## 🟦 2. Jalankan Aplikasi GUI
Gunakan perintah:

python certificate_viewer_gui.py

Aplikasi GUI akan muncul.

---

## 🟦 3. Masukkan Domain
Pada kolom **Domain**, masukkan alamat website.

Contoh:
www.google.com

Port biarkan default: `443`.

---

## 🟦 4. Klik Tombol “Ambil Sertifikat”
Aplikasi akan menampilkan:

- Subject
- Issuer
- Validity
- Signature Algorithm
- Public Key Information (RSA/ECC)
- Fingerprint
- SAN
- Semua Extensions

---

## 🟦 5. Tombol-Tombol Fitur Tambahan

### ✔ **Simpan PEM**
Menyimpan sertifikat menjadi file `.pem`.

### ✔ **Export JSON**
Mengekspor informasi sertifikat menjadi file `.json`.

### ✔ **Batch Mode**
- Gunakan file `.txt` berisi domain (satu per baris)
- Aplikasi membuat file JSON berisi hasil analisis semua domain

---

# 🖼️ **Contoh Output Sertifikat**
Domain: www.google.com

Subject: CN=www.google.com, O=Google LLC, L=Mountain View, ST=California, C=US
Issuer : CN=GTS CA 1O1, O=Google Trust Services, C=US

Masa Berlaku:
Dari : 2025-09-15 08:12:34 UTC
Sampai: 2026-01-08 08:12:33 UTC
Status : VALID

Algoritma Tanda Tangan: sha256WithRSAEncryption
Informasi Kunci Publik: RSA (2048 bits)

Fingerprints:
SHA-256 : AB:CD:EF:...
SHA-1 : 11:22:33:...

Subject Alternative Names (SAN):

www.google.com

google.com

Extensions:

keyUsage: Digital Signature, Key Encipherment

basicConstraints: CA:FALSE

extendedKeyUsage: serverAuth

authorityKeyIdentifier: KeyID:...

yaml
Salin kode

---

### 🔗 **GitHub Repository**
https://github.com/Ucuk/Anatomi-Gembok-HTTPS-Certificate-Viewer

---

# 📝 **Lisensi**
MIT License
© 2025 – Kelompok 5
