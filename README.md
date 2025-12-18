# Api-Keamanan-Kriptografi
Implementasi API keamanan berbasis FastAPI untuk layanan kriptografi. Sistem mendukung registrasi kunci publik, autentikasi pengguna menggunakan JWT, tanda tangan digital Ed25519 untuk menjaga keaslian dan integritas data, serta relay pesan dan pencatatan aktivitas sebagai audit trail.

# Penjelasan File api.py
File api.py merupakan inti dari layanan API keamanan yang dibangun menggunakan FastAPI. File ini berfungsi sebagai server utama yang menangani proses registrasi pengguna, autentikasi, verifikasi tanda tangan digital, relay pesan, serta pencatatan aktivitas sistem (audit trail).

Pada bagian awal, api.py mendefinisikan konfigurasi utama seperti:

JWT (JSON Web Token) untuk autentikasi dan manajemen sesi pengguna.
Direktori data/ yang digunakan untuk menyimpan:
1. users.json → data pengguna dan kunci publik
2. inbox.json → pesan masuk pengguna
3. activity_log.json → catatan aktivitas sistem
Semua data disimpan dalam format JSON untuk memudahkan pengelolaan dan pembacaan.

Autentikasi dan Manajemen Sesi (JWT)
API ini menggunakan JWT untuk memastikan hanya pengguna yang terautentikasi yang dapat mengakses endpoint sensitif.
Alur autentikasi:
1. Pengguna melakukan registrasi dengan mengirim username dan public key.
2. Pengguna melakukan login melalui endpoint /token.
3. Server menghasilkan JWT token yang digunakan sebagai Bearer Token pada request selanjutnya.
4. Endpoint seperti /verify, /relay, dan /inbox hanya bisa diakses jika token valid.

Tanda Tangan Digital (Ed25519)
API mendukung verifikasi tanda tangan digital menggunakan algoritma Ed25519, yang digunakan untuk:
1. Memastikan keaslian pengirim
2. Menjamin integritas pesan atau dokumen
Fitur ini tersedia melalui:
/verify-text → verifikasi tanda tangan pesan teks
/verify-pdf → verifikasi tanda tangan file PDF
Jika tanda tangan tidak valid, server akan menolak request.

Relay Pesan
API menyediakan layanan relay pesan yang aman:
/relay-text → mengirim pesan teks ke pengguna lain
/relay-pdf → mengirim file PDF ke pengguna lain
Sebelum pesan diteruskan, server akan:
1. Memverifikasi tanda tangan pengirim
2. Menyimpan pesan ke inbox penerima

Global Activity Logger (Audit Trail)
api.py mengintegrasikan middleware logger yang mencatat setiap aktivitas API, meliputi:
1. Waktu akses
2. Endpoint yang diakses
3. Metode HTTP
4. Pengguna
5. Status response
Data ini disimpan dalam activity_log.json dan berfungsi sebagai audit trail untuk keperluan monitoring dan evaluasi keamanan.

# Penjelasan File client.py
File client.py berfungsi sebagai sisi klien dalam sistem keamanan ini. File ini digunakan untuk membuat pasangan kunci kriptografi (private key dan public key) menggunakan algoritma Ed25519, yang nantinya akan digunakan dalam proses tanda tangan digital dan verifikasi pada server API.

# Penjelasan File digital-signature.py
File digital_signature.py berfungsi untuk melakukan proses pembuatan tanda tangan digital (digital signature) pada sisi klien menggunakan algoritma Ed25519. Tanda tangan digital ini digunakan untuk menjamin keaslian pengirim dan integritas pesan atau dokumen sebelum dikirim ke server API.

# Penjelasan File main.py
File main.py berfungsi sebagai entry point untuk menjalankan server API yang didefinisikan pada file api.py. File ini bertanggung jawab untuk menjalankan aplikasi FastAPI menggunakan Uvicorn sebagai ASGI server.

# Penjelasan File pyproject.toml
File ini berisi konfigurasi proyek Python dan daftar dependensi yang dibutuhkan.
Di dalamnya terdapat informasi nama proyek, versi, deskripsi, serta versi Python yang digunakan (Python 3.10).

Daftar dependensi mencakup library utama seperti FastAPI untuk membangun API, cryptography untuk fitur keamanan dan tanda tangan digital, uvicorn sebagai server, serta library pendukung lainnya. File ini membantu memastikan proyek dapat dijalankan dengan lingkungan yang konsisten.

# Penjelasan File uv.lock
File uv.lock adalah file lock dependency yang dibuat otomatis oleh tool uv.
File ini menyimpan versi pasti (exact version) dari seluruh library dan dependensi proyek, termasuk dependensi turunan.
Tujuannya adalah memastikan proyek dijalankan dengan lingkungan yang konsisten di semua komputer, sehingga tidak terjadi error akibat perbedaan versi library.
File ini tidak perlu diedit secara manual dan sebaiknya tetap disertakan di repository.

#Penjelasan Folder punkhazard-keys
Folder punkhazard-keys digunakan untuk menyimpan pasangan kunci kriptografi Ed25519, yaitu private key dan public key milik pengguna.
Kunci ini digunakan untuk proses tanda tangan digital dan verifikasi keaslian serta integritas pesan atau dokumen yang dikirim melalui sistem.
