"""Tests for common/crypto_utils.py's validate_certificate_bundle() - the
pre-write check the client's retrieve_certificate() (common/client_utils.py)
runs on a downloaded key/cert/intermediate bundle before writing any file to
disk: general integrity, certificate-matches-key, and intermediate(s)
correctly chain to the certificate.

Run with:
    python3 -m unittest discover -s tests -v
from the repository root (with the project installed, or PYTHONPATH=src set).
"""
import datetime
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sslcrtsrv.common.crypto_utils import validate_certificate_bundle


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def _key_pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()


def _cert_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _make_ca(common_name="Test CA"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = _utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_leaf(common_name, issuer_key, issuer_cert, leaf_key=None):
    leaf_key = leaf_key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = _utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(issuer_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(issuer_key, hashes.SHA256())
    )
    return leaf_key, cert


class TestValidateCertificateBundle(unittest.TestCase):
    def setUp(self):
        self.ca_key, self.ca_cert = _make_ca()
        self.leaf_key, self.leaf_cert = _make_leaf("host.example.com", self.ca_key, self.ca_cert)
        self.other_ca_key, self.other_ca_cert = _make_ca("Other CA")

    def test_matching_key_cert_and_intermediate_validates(self):
        ok, error = validate_certificate_bundle(
            key_pem=_key_pem(self.leaf_key), cert_pem=_cert_pem(self.leaf_cert),
            intermediate_pem=_cert_pem(self.ca_cert))
        self.assertTrue(ok, error)
        self.assertIsNone(error)

    def test_cert_key_mismatch_is_rejected(self):
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ok, error = validate_certificate_bundle(
            key_pem=_key_pem(wrong_key), cert_pem=_cert_pem(self.leaf_cert))
        self.assertFalse(ok)
        self.assertIn("match", error)

    def test_intermediate_that_did_not_issue_the_cert_is_rejected(self):
        ok, error = validate_certificate_bundle(
            key_pem=_key_pem(self.leaf_key), cert_pem=_cert_pem(self.leaf_cert),
            intermediate_pem=_cert_pem(self.other_ca_cert))
        self.assertFalse(ok)
        self.assertIn("chain", error)

    def test_malformed_certificate_is_rejected_cleanly(self):
        ok, error = validate_certificate_bundle(cert_pem="not a certificate")
        self.assertFalse(ok)
        self.assertIn("Certificate", error)

    def test_malformed_key_is_rejected_cleanly(self):
        ok, error = validate_certificate_bundle(key_pem="not a key", cert_pem=_cert_pem(self.leaf_cert))
        self.assertFalse(ok)
        self.assertIn("key", error)

    def test_malformed_intermediate_is_rejected_cleanly(self):
        ok, error = validate_certificate_bundle(
            cert_pem=_cert_pem(self.leaf_cert), intermediate_pem="not a certificate")
        self.assertFalse(ok)
        self.assertIn("Intermediate", error)

    def test_cert_only_with_no_key_or_intermediate_validates(self):
        ok, error = validate_certificate_bundle(cert_pem=_cert_pem(self.leaf_cert))
        self.assertTrue(ok, error)

    def test_nothing_provided_validates_trivially(self):
        ok, error = validate_certificate_bundle()
        self.assertTrue(ok)
        self.assertIsNone(error)

    def test_multi_certificate_intermediate_chain_validates(self):
        # A root -> intermediate -> leaf chain, with both CA certs bundled
        # together in one PEM blob the way server responses concatenate them.
        root_key, root_cert = _make_ca("Root CA")
        mid_key, mid_cert = _make_leaf("Mid CA", root_key, root_cert)
        leaf_key, leaf_cert = _make_leaf("chained.example.com", mid_key, mid_cert)
        bundle = _cert_pem(mid_cert) + _cert_pem(root_cert)
        ok, error = validate_certificate_bundle(
            key_pem=_key_pem(leaf_key), cert_pem=_cert_pem(leaf_cert), intermediate_pem=bundle)
        self.assertTrue(ok, error)

    def test_broken_link_further_down_the_chain_is_rejected(self):
        # leaf is correctly issued by self.ca_cert (first link OK), but the
        # bundle also claims self.ca_cert was issued by an unrelated mid_cert
        # (second link broken) - the walk past the first intermediate must
        # still catch this.
        root_key, root_cert = _make_ca("Root CA")
        _, mid_cert = _make_leaf("Mid CA", root_key, root_cert)
        leaf_key, leaf_cert = _make_leaf("chained.example.com", self.ca_key, self.ca_cert, leaf_key=self.leaf_key)
        bundle = _cert_pem(self.ca_cert) + _cert_pem(mid_cert)
        ok, error = validate_certificate_bundle(
            key_pem=_key_pem(leaf_key), cert_pem=_cert_pem(leaf_cert), intermediate_pem=bundle)
        self.assertFalse(ok)
        self.assertIn("chain", error)


if __name__ == "__main__":
    unittest.main()
