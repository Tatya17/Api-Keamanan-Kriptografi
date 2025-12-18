import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Nama pemilik key
Nama = "ruthtatia"

OUT_DIR = "punkhazard-keys"
os.makedirs(OUT_DIR, exist_ok=True)

# Generate Key Pair
priv = ed25519.Ed25519PrivateKey.generate()
pub  = priv.public_key()

# Simpan Private Key
with open(f"{OUT_DIR}/{Nama}_priv.pem", "wb") as f:
    f.write(
        priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
    )

# Simpan Public Key
with open(f"{OUT_DIR}/{Nama}_pub.pem", "wb") as f:
    f.write(
        pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print(f"Ed25519 key pair generated for {Nama}")