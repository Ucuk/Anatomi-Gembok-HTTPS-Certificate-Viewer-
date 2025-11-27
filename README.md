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
Domain: unm.ac.id

Subject: commonName=unm.ac.id
Issuer : countryName=US, organizationName=Google Trust Services, commonName=WE1

Masa Berlaku:
  Dari  : 2025-11-21 00:17:48 UTC
  Sampai: 2026-02-19 01:15:13 UTC
  Status: VALID

Algoritma Tanda Tangan: ecdsa-with-SHA256
Informasi Kunci Publik: Elliptic Curve (secp256r1)

Fingerprints:
  SHA-256: 6A:A3:B9:4A:89:6F:B5:D0:EC:BB:37:34:F8:F4:F0:87:84:84:53:4D:2D:EB:42:8A:44:BA:B7:8B:8E:F3:46:7C
  SHA-1  : CD:98:30:A2:1D:39:22:32:DA:93:41:98:6F:7E:65:2C:8E:05:7D:C1

Subject Alternative Names (SAN):
  - unm.ac.id
  - *.unm.ac.id

---

### 🔗 **GitHub Repository**
https://github.com/Ucuk/Anatomi-Gembok-HTTPS-Certificate-Viewer-

---

# 📝 **Lisensi**
MIT License
© 2025 – Kelompok 5
