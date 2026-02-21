
import datetime

# ── Cryptographic primitives from the 'cryptography' library ──────────────────
from cryptography import x509                              # X.509 certificate builder
from cryptography.x509.oid import NameOID                  # standard certificate field names
from cryptography.hazmat.primitives import hashes          # SHA-256 hashing algorithm
from cryptography.hazmat.primitives.asymmetric import rsa  # RSA key generation
from cryptography.hazmat.primitives import serialization   # PEM encoding for saving to disk
import ipaddress                                           # for adding IP addresses to the cert


def generate_self_signed_cert():
    """
    Generate a self-signed TLS certificate and private key for local HTTPS.

    Produces two files in the current directory:
      - key.pem  : the RSA private key (keep this secret — never commit to git)
      - cert.pem : the self-signed X.509 certificate (given to clients to trust)

    A self-signed cert is fine for development / testing.
    In production, use a certificate issued by a real CA (e.g. Let's Encrypt).
    """

    # ── Step 1: Generate a 2048-bit RSA private key ───────────────────────────
    # public_exponent=65537 is the standard safe value for RSA
    # key_size=2048 provides strong encryption while remaining fast
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # ── Step 2: Save the private key to disk as key.pem ───────────────────────
    with open("key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,              # PEM = base64-encoded text format
            format=serialization.PrivateFormat.TraditionalOpenSSL,  # standard PKCS#1 format
            encryption_algorithm=serialization.NoEncryption(),      # no passphrase on the key file
            # NOTE: in production, use BestAvailableEncryption("passphrase") instead
        ))

    # ── Step 3: Define the certificate identity fields ────────────────────────
    # For a self-signed cert, the subject (who the cert is for) and the
    # issuer (who signed it) are the same entity — us.
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,             u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,   u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME,            u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,        u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME,              u"localhost"),  # hostname the cert is valid for
    ])

    # ── Step 4: Build the certificate ─────────────────────────────────────────
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)       # who the certificate belongs to
        .issuer_name(issuer)         # who signed/issued it (same as subject for self-signed)
        .public_key(key.public_key()) # embed the RSA public key so clients can encrypt to us
        .serial_number(x509.random_serial_number())  # unique random ID for this certificate
        .not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)   # valid starting right now
        )
        .not_valid_after(
            # Certificate expires 365 days from now
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        )
        # ── Subject Alternative Names (SANs) ──────────────────────────────────
        # Modern browsers and HTTP clients require SANs — they ignore Common Name alone.
        # We add all the hostnames/IPs that the Flutter app might connect from.
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(u"localhost"),          # browser / device connecting as 'localhost'
                x509.DNSName(u"*.localhost"),        # any subdomain of localhost
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),  # loopback IP (same machine)
                x509.IPAddress(ipaddress.IPv4Address("0.0.0.0")),    # bind-all address
            ]),
            critical=False,   # SAN is informational; setting critical=True would break some clients
        )
        # ── Step 5: Sign the certificate with our private key ─────────────────
        # SHA-256 is the standard secure hashing algorithm for certificate signatures
        .sign(key, hashes.SHA256())
    )

    # ── Step 6: Save the signed certificate to disk as cert.pem ──────────────
    with open("cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))  # PEM = human-readable base64

    print("Successfully generated key.pem and cert.pem")


# Entry point — only runs when this script is executed directly (not imported)
if __name__ == "__main__":
    generate_self_signed_cert()
