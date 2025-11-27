# 🔐 Certificate Viewer - GUI (Ultimate Dewa Version)
**Kelompok 5 – Proyek Anatomi Gembok HTTPS (PKI & X.509 Certificate Viewer)**  
Mata Kuliah: **Kriptografi**  
Tahun: **2025**

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python)
![GUI](https://img.shields.io/badge/GUI-Tkinter-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 📌 Deskripsi Proyek
Certificate Viewer adalah aplikasi GUI untuk memeriksa dan menganalisis **Sertifikat Digital X.509** dari sebuah domain HTTPS secara real-time.

Aplikasi ini dibuat untuk memenuhi Proyek Kelompok 5:  
**"Anatomi Gembok HTTPS (Certificate Viewer)"**, dengan tujuan memahami:

- Bagaimana HTTPS bekerja  
- Struktur sertifikat digital  
- Peran PKI (Public Key Infrastructure)  
- Validasi identitas server melalui TLS  

Aplikasi dikembangkan menggunakan **Python + Tkinter + Cryptography**, dan mendukung:

✔ RSA Public Key  
✔ Elliptic Curve (ECC) seperti `secp256r1`  
✔ DSA Key  
✔ SAN (Subject Alternative Names)  
✔ Fingerprint SHA-256 & SHA-1  
✔ PEM Export  
✔ JSON Export  
✔ Batch Mode (analisis banyak domain otomatis)

---

## 🚀 Fitur Utama
### 🔹 1. Ambil Sertifikat Website (HTTPS)
Aplikasi melakukan koneksi TLS/SSL dan mengambil sertifikat **langsung dari server**.

### 🔹 2. Parse Sertifikat X.509 Lengkap
Informasi yang ditampilkan:

- Subject (CN, O, L, ST, C)  
- Issuer / Certificate Authority  
- Valid From & Valid To  
- Status VALID / EXPIRED  
- Signature Algorithm  
- Public Key (RSA/ECC/DSA)  
- Fingerprint SHA-256  
- Fingerprint SHA-1  
- SAN (Domain alternatif)  
- Semua Extensions  

### 🔹 3. Export & Save
- Simpan sertifikat ke format **PEM**
- Export detail sertifikat ke **JSON**

### 🔹 4. Batch Mode
Analisis banyak domain sekaligus dari file `.txt`.

### 🔹 5. Tampilan GUI
Antarmuka Tkinter yang sederhana, bersih, dan mudah digunakan.
