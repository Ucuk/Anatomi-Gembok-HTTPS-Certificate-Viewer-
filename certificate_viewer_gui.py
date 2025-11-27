import socket
import ssl
import datetime
import json
import traceback
import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

# -------------------------
# Helper: fetch certificate
# -------------------------
def fetch_certificate(domain: str, port: int = 443, timeout: int = 6) -> bytes:
    """
    Create TCP connection and perform TLS handshake (SNI-aware),
    return DER-encoded certificate (leaf) as bytes.
    """
    context = ssl.create_default_context()
    # We don't need to validate chain here — we only want raw cert bytes
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((domain, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            der = ssock.getpeercert(binary_form=True)
            return der

# -------------------------
# Helper: parse certificate
# -------------------------
def parse_certificate(der_bytes: bytes) -> x509.Certificate:
    return x509.load_der_x509_certificate(der_bytes)

# -------------------------
# Helper: format X.509 Name
# -------------------------
def format_name(name: x509.Name) -> str:
    parts = []
    # rfc4514 order: keep whatever x509 gives
    for rd in name.rdns:
        for attr in rd:
            try:
                key = attr.oid._name
            except Exception:
                key = attr.oid.dotted_string
            parts.append(f"{key}={attr.value}")
    return ", ".join(parts)

# -------------------------
# Helper: fingerprint
# -------------------------
def fingerprint_hex(cert: x509.Certificate, algo=hashes.SHA256()) -> str:
    fp = cert.fingerprint(algo)
    return ":".join(f"{b:02X}" for b in fp)

# -------------------------
# Helper: get SAN list
# -------------------------
def get_san_list(cert: x509.Certificate):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        return []

# -------------------------
# Helper: key info (robust)
# -------------------------
def get_public_key_info(pubkey) -> str:
    """
    Return human-friendly public key info:
    - RSA (2048 bits)
    - Elliptic Curve (secp256r1)
    - DSA (size)
    Fallback prints the type.
    """
    try:
        # RSA
        if isinstance(pubkey, rsa.RSAPublicKey):
            return f"RSA ({pubkey.key_size} bits)"
        # EC
        if isinstance(pubkey, ec.EllipticCurvePublicKey):
            try:
                curve_name = pubkey.curve.name
            except Exception:
                # sometimes curve attribute exists but name attr missing
                curve_name = getattr(getattr(pubkey, "curve", None), "name", "UnknownCurve")
            return f"Elliptic Curve ({curve_name})"
        # DSA
        if isinstance(pubkey, dsa.DSAPublicKey):
            try:
                size = pubkey.key_size
                return f"DSA ({size} bits)"
            except Exception:
                return "DSA (unknown size)"
    except Exception:
        # Some wrapper types might not be instance-checkable; try duck-typing
        try:
            # try to detect RSA by presence of public_numbers and modulus attribute
            pn = getattr(pubkey, "public_numbers", None)
            if pn:
                nums = pubkey.public_numbers()
                if hasattr(nums, "n"):
                    # RSA-like
                    n = nums.n
                    bitlen = n.bit_length()
                    return f"RSA (~{bitlen} bits)"
        except Exception:
            pass
    # fallback
    return f"Unknown Public Key Type ({type(pubkey)})"

# -------------------------
# Build display text
# -------------------------
def build_display_text(cert: x509.Certificate, domain: str) -> str:
    now = datetime.datetime.datetime.utcnow() if False else datetime.datetime.utcnow()
    lines = []
    lines.append(f"Domain: {domain}")
    lines.append("")

    # Subject & Issuer
    try:
        lines.append(f"Subject: {format_name(cert.subject)}")
    except Exception:
        lines.append("Subject: (could not parse)")

    try:
        lines.append(f"Issuer : {format_name(cert.issuer)}")
    except Exception:
        lines.append("Issuer : (could not parse)")

    lines.append("")
    # Validity
    try:
        nb = cert.not_valid_before
        na = cert.not_valid_after
        status = "VALID" if (nb <= now <= na) else "EXPIRED / NOT VALID"
        lines.append("Masa Berlaku:")
        lines.append(f"  Dari  : {nb} UTC")
        lines.append(f"  Sampai: {na} UTC")
        lines.append(f"  Status: {status}")
    except Exception:
        lines.append("Masa Berlaku: (tidak tersedia)")

    lines.append("")
    # Signature Algorithm
    try:
        sigalgo = getattr(cert.signature_algorithm_oid, "_name", cert.signature_algorithm_oid.dotted_string)
        lines.append(f"Algoritma Tanda Tangan: {sigalgo}")
    except Exception:
        lines.append("Algoritma Tanda Tangan: (tidak tersedia)")

    # Public Key Info
    try:
        pk = cert.public_key()
        pkinfo = get_public_key_info(pk)
        lines.append(f"Informasi Kunci Publik: {pkinfo}")
    except Exception as e:
        lines.append(f"Informasi Kunci Publik: (gagal membaca) - {e}")

    lines.append("")
    # Fingerprints
    try:
        lines.append("Fingerprints:")
        lines.append(f"  SHA-256: {fingerprint_hex(cert, hashes.SHA256())}")
        lines.append(f"  SHA-1  : {fingerprint_hex(cert, hashes.SHA1())}")
    except Exception:
        lines.append("Fingerprints: (gagal)")

    lines.append("")
    # SAN
    sans = get_san_list(cert)
    lines.append("Subject Alternative Names (SAN):")
    if sans:
        for s in sans:
            lines.append(f"  - {s}")
    else:
        lines.append("  (Tidak ada SAN)")

    lines.append("")
    # Extensions (human readable where possible)
    lines.append("Extensions:")
    try:
        for ext in cert.extensions:
            try:
                name = ext.oid._name
            except Exception:
                name = ext.oid.dotted_string
            # For certain well-known extensions, provide concise info
            try:
                if name == "basicConstraints":
                    lines.append(f" - {name}: {ext.value}")
                elif name == "keyUsage":
                    lines.append(f" - {name}: {ext.value}")
                elif name == "subjectKeyIdentifier":
                    lines.append(f" - {name}: {ext.value.digest.hex()}")
                elif name == "authorityKeyIdentifier":
                    lines.append(f" - {name}: {ext.value.key_identifier.hex() if getattr(ext.value, 'key_identifier', None) else ext.value}")
                elif name == "subjectAltName":
                    lines.append(f" - {name}: {ext.value}")
                else:
                    lines.append(f" - {name}: {ext.value}")
            except Exception:
                # generic fallback
                lines.append(f" - {name}: (value unreadable)")
    except Exception:
        lines.append(" - (gagal membaca extensions)")

    return "\n".join(lines)

# -------------------------
# GUI functions
# -------------------------
def fetch_and_display():
    domain = entry_domain.get().strip()
    if not domain:
        messagebox.showerror("Error", "Domain tidak boleh kosong.")
        return
    try:
        port = int(entry_port.get().strip())
    except Exception:
        port = 443

    try:
        text_output.delete(1.0, tk.END)
        text_output.insert(tk.END, f" Mengambil sertifikat dari {domain}:{port} ...\n")
        der = fetch_certificate(domain, port)
        cert = parse_certificate(der)
        out = build_display_text(cert, domain)
        text_output.delete(1.0, tk.END)
        text_output.insert(tk.END, out)
        # store last cert & der
        root_ctx["last_der"] = der
        root_ctx["last_cert"] = cert
    except Exception as e:
        text_output.delete(1.0, tk.END)
        text_output.insert(tk.END, f"ERROR: {e}\n\n{traceback.format_exc()}")

def save_pem():
    if "last_der" not in root_ctx:
        messagebox.showwarning("Peringatan", "Belum ada sertifikat. Ambil sertifikat terlebih dahulu.")
        return
    der = root_ctx["last_der"]
    try:
        cert = x509.load_der_x509_certificate(der)
        pem = cert.public_bytes(serialization.Encoding.PEM)
    except Exception:
        # fallback: wrap DER -> PEM via generic
        try:
            pem = ssl.DER_cert_to_PEM_cert(der).encode("utf-8")
        except Exception as e:
            messagebox.showerror("Error", f"Gagal konversi DER->PEM: {e}")
            return
    fpath = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
    if fpath:
        with open(fpath, "wb") as f:
            f.write(pem)
        messagebox.showinfo("Sukses", f"Sertifikat disimpan ke: {fpath}")

def export_json():
    if "last_cert" not in root_ctx:
        messagebox.showwarning("Peringatan", "Belum ada sertifikat. Ambil sertifikat terlebih dahulu.")
        return
    cert = root_ctx["last_cert"]
    domain = entry_domain.get().strip()
    obj = {
        "domain": domain,
        "subject": format_name(cert.subject),
        "issuer": format_name(cert.issuer),
        "valid_from": cert.not_valid_before.isoformat(),
        "valid_to": cert.not_valid_after.isoformat(),
        "signature_algorithm": getattr(cert.signature_algorithm_oid, "_name", cert.signature_algorithm_oid.dotted_string),
        "public_key": get_public_key_info(cert.public_key()),
        "sha256": fingerprint_hex(cert, hashes.SHA256()),
        "sha1": fingerprint_hex(cert, hashes.SHA1()),
        "san": get_san_list(cert),
        "extensions": {}
    }
    # extensions as strings
    try:
        for ext in cert.extensions:
            try:
                name = ext.oid._name
            except Exception:
                name = ext.oid.dotted_string
            obj["extensions"][name] = str(ext.value)
    except Exception:
        obj["extensions"] = {"error": "cannot parse extensions"}

    fpath = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json"), ("All", "*.*")])
    if fpath:
        with open(fpath, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, ensure_ascii=False)
        messagebox.showinfo("Sukses", f"JSON tersimpan: {fpath}")

def batch_mode():
    fpath = filedialog.askopenfilename(title="Pilih file teks berisi daftar domain (satu per baris)")
    if not fpath:
        return
    out = []
    with open(fpath, "r", encoding="utf-8") as fh:
        domains = [line.strip() for line in fh if line.strip()]
    for d in domains:
        try:
            der = fetch_certificate(d)
            cert = parse_certificate(der)
            item = {
                "domain": d,
                "subject": format_name(cert.subject),
                "issuer": format_name(cert.issuer),
                "valid_from": cert.not_valid_before.isoformat(),
                "valid_to": cert.not_valid_after.isoformat(),
                "public_key": get_public_key_info(cert.public_key()),
                "sha256": fingerprint_hex(cert, hashes.SHA256())
            }
        except Exception as e:
            item = {"domain": d, "error": str(e)}
        out.append(item)
    savepath = filedialog.asksaveasfilename(defaultextension=".json")
    if savepath:
        with open(savepath, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2, ensure_ascii=False)
        messagebox.showinfo("Selesai", f"Hasil batch disimpan: {savepath}")

# -------------------------
# Build GUI
# -------------------------
root = tk.Tk()
root.title("Certificate Viewer - GUI (Ultimate Dewa) - Kelompok 5")
root.geometry("940x720")

root_ctx = {}

frame_top = tk.Frame(root)
frame_top.pack(pady=8, padx=8, anchor="w")

tk.Label(frame_top, text="Domain:", font=("Segoe UI", 11)).grid(row=0, column=0, sticky="w")
entry_domain = tk.Entry(frame_top, width=48, font=("Consolas", 11))
entry_domain.grid(row=0, column=1, padx=6)

tk.Label(frame_top, text="Port:", font=("Segoe UI", 11)).grid(row=0, column=2, sticky="w", padx=(12,0))
entry_port = tk.Entry(frame_top, width=6, font=("Consolas", 11))
entry_port.grid(row=0, column=3, padx=6)
entry_port.insert(0, "443")

btn_fetch = tk.Button(frame_top, text="Ambil Sertifikat", width=18, command=fetch_and_display, bg="#1976D2", fg="white")
btn_fetch.grid(row=0, column=4, padx=(10,0))

btn_save = tk.Button(frame_top, text="Simpan PEM", width=12, command=save_pem)
btn_save.grid(row=0, column=5, padx=6)

btn_json = tk.Button(frame_top, text="Export JSON", width=12, command=export_json)
btn_json.grid(row=0, column=6, padx=6)

btn_batch = tk.Button(frame_top, text="Batch (file)", width=12, command=batch_mode)
btn_batch.grid(row=0, column=7, padx=6)

text_output = scrolledtext.ScrolledText(root, width=112, height=38, font=("Consolas", 10))
text_output.pack(padx=8, pady=8)

# Footer / short help
lbl_help = tk.Label(root, text="Masukkan domain (mis. www.google.com) lalu klik 'Ambil Sertifikat'. Gunakan 'Batch' untuk file domain list.", anchor="w")
lbl_help.pack(fill="x", padx=8, pady=(0,8))

root.mainloop()
