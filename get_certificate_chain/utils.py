import ssl
from typing import List
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

import certifi
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID
from .exceptions import *


def get_certificate(host: str, port: int) -> x509.Certificate:
    """Connect to a server and retrieve the SSL certificate.

    Arguments:
        host -- the host to connect to.
        port -- the port to connect to.

    Returns:
        The SSL certificate of the server.
    """
    cert_pem = ssl.get_server_certificate((host, port))
    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    return cert


def ssl_certificate_to_string(ssl_certificate: x509.Certificate) -> str:
    return ssl_certificate.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")


def return_cert_aia(ssl_certificate: x509.Certificate) -> x509.Extensions:
    """Get the Authority Information Access (AIA) extension from a certificate.

    Arguments:
        ssl_certificate -- the SSL certificate.

    Returns:
        The AIA extension or None if not found.
    """
    try:
        return ssl_certificate.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )
    except x509.ExtensionNotFound:
        return None


def get_certificate_from_uri(uri: str) -> x509.Certificate:
    """Retrieve a certificate from the given URI.

    Arguments:
        uri -- the URI to get the certificate from.

    Returns:
        The certificate from the URI or None if there was an error.
    """
    cert = None

    try:
        with urlopen(uri) as response:
            if response.getcode() == 200:
                aia_content = response.read()
                ssl_certificate = ssl.DER_cert_to_PEM_cert(aia_content)
                cert = x509.load_pem_x509_certificate(
                    ssl_certificate.encode("ascii"), default_backend()
                )
    except (HTTPError, URLError):
        pass

    return cert


def return_cert_aia_list(ssl_certificate: x509.Certificate) -> list:
    """Get the list of AIA URIs from a certificate.

    Arguments:
        ssl_certificate -- the SSL certificate.

    Returns:
        A list of AIA URIs.
    """
    aia_uri_list = []

    for extension in ssl_certificate.extensions:
        cert_value = extension.value

        if isinstance(cert_value, x509.AuthorityInformationAccess):
            for item in cert_value:
                if item.access_method._name == "caIssuers":
                    aia_uri_list.append(item.access_location._value)

    return aia_uri_list


def return_cert_aki(ssl_certificate):
    """Get the Authority Key Identifier (AKI) from a certificate.

    Arguments:
        ssl_certificate -- the SSL certificate.

    Returns:
        The AKI extension or None if not found.
    """
    try:
        return ssl_certificate.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        )
    except x509.ExtensionNotFound:
        return None


def return_cert_ski(ssl_certificate):
    """Get the Subject Key Identifier (SKI) from a certificate.

    Arguments:
        ssl_certificate -- the SSL certificate.

    Returns:
        The SKI extension.
    """
    try:
        return ssl_certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
    except x509.ExtensionNotFound:
        return None


def load_ca_cert_chain(ca_cert_text: str) -> List[x509.Certificate]:
    """Obtains the list of certificates in a given text.

    Arguments:
        ca_cert_text -- the text to search for certificates.

    Returns:
        A List of certificates.
    """
    ca_cert_store = []

    lines = ca_cert_text.splitlines()
    index = 0
    certificate_start = 0
    in_cert = False  # variable to know if i'm in a certificate o not

    while index < len(lines):
        current_line = lines[index]

        if not in_cert:
            if current_line == "-----BEGIN CERTIFICATE-----":
                certificate_start = index
                in_cert = True
        else:
            if current_line == "-----END CERTIFICATE-----":
                ca_cert = "\n".join(lines[certificate_start : index + 1])
                cert = x509.load_pem_x509_certificate(
                    ca_cert.encode(), default_backend()
                )
                ca_cert_store.append(cert)
                in_cert = False
        index += 1

    return ca_cert_store


def get_root_certificate(cert_aki_value: bytes) -> x509.Certificate or None:
    """Obtains a root certificate corresponding to a given AKI value.

    Arguments:
        cert_aki_value -- the AKI value to search for.

    Returns:
        A root certificate or None in case the certificate could not be found.
    """
    root_certificate = None

    if cert_aki_value:
        with open(certifi.where()) as cacert_pem:
            ca_root_store = load_ca_cert_chain(cacert_pem.read())

        for root_ca_certificate in ca_root_store:
            root_ca_ski = return_cert_ski(root_ca_certificate)
            root_ca_ski_value = root_ca_ski._value.digest if root_ca_ski else None

            if root_ca_ski_value == cert_aki_value:
                root_certificate = root_ca_certificate
                break

    return root_certificate


def walk_the_chain(
    ssl_certificate: x509.Certificate, max_depth: int = 4
) -> List[x509.Certificate]:
    """Builds all the chain of SSL certificates of a given one.

    Arguments:
        ssl_certificate -- an SSL certificate.

    Keyword Arguments:
        max_depth -- the maximum depth to iterate searching
            for the end of the chain (default: {4})

    Raises:
        CertificateNotFound: raises when the chain breaks,
            because it couldn't find the next certificate.
        RootCertificateNotFound: raises when, at the end of the chain,
            it couldn't find the root certificate.

    Returns:
        List of the certificates conforming the chain.
    """

    depth = 0
    end_of_chain = False
    certificate = ssl_certificate
    cert_chain = [certificate]

    while depth < max_depth and not end_of_chain:
        aia_uri_list = return_cert_aia_list(certificate)

        if aia_uri_list:
            for item in aia_uri_list:
                next_cert = get_certificate_from_uri(item)

                if next_cert:
                    cert_chain.append(next_cert)
                    certificate = next_cert
                else:
                    raise CertificateNotFound("Could not retrieve certificate.")
        else:
            root_ca_certificate = get_root_certificate(
                return_cert_aki(certificate)._value.key_identifier
            )
            if root_ca_certificate:
                cert_chain.append(root_ca_certificate)
            else:
                raise RootCertificateNotFound(
                    "Could not retrieve the root certificate."
                )
            end_of_chain = True
        depth += 1

    return cert_chain


def chain_to_string(cert_chain: List[x509.Certificate]) -> str:
    """Convert a list of certificates to a string.

    Arguments:
        cert_chain -- the list of certificates.

    Returns:
        A string representing the list of certificates.
    """
    chain_as_string = ""
    for cert in cert_chain:
        chain_as_string += ssl_certificate_to_string(cert)

    return chain_as_string
