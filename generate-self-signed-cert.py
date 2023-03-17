import os

import OpenSSL
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Generate a private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Serialize the private key to PEM format
pem_private_key = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Generate a public key
public_key = private_key.public_key()

# Serialize the public key to PEM format
pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Create a self-signed certificate
cert = OpenSSL.crypto.X509()
cert.set_version(2)
cert.set_serial_number(1000)
cert.get_subject().CN = "MyMobileDevice"
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # 1 year expiration
cert.set_pubkey(public_key)
cert.set_issuer(cert.get_subject())

# Sign the certificate with the private key
cert.sign(private_key, "sha256")

# Serialize the certificate to PEM format
pem_certificate = OpenSSL.crypto.dump_certificate(
    OpenSSL.crypto.FILETYPE_PEM, cert
)

# Write the private key, public key, and certificate to disk
with open(os.path.abspath('private_key.pem'), 'wb') as f:
    f.write(pem_private_key)

with open(os.path.abspath('public_key.pem'), 'wb') as f:
    f.write(pem_public_key)

with open(os.path.abspath('certificate.pem'), 'wb') as f:
    f.write(pem_certificate)
