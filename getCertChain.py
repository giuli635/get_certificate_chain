# Description:     Get the certificate chain from a website.
# Author:          TheScriptGuy
# Last modified:   2023-03-20
# Version:         0.04

import ssl
import socket
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization

import requests
import argparse
import sys
import os
import glob
import re

scriptVersion = "0.04"
maxDepth = 4
certChain = []


def parseArguments():
    """Create argument options and parse through them to determine what to do with script."""
    # Instantiate the parser
    parser = argparse.ArgumentParser(
        description="Get Certificate Chain v" + scriptVersion
    )

    # Optional arguments
    parser.add_argument(
        "--hostname",
        default="www.google.com:443",
        help="The hostname:port pair that the script should connect to. Defaults to www.google.com:443.",
    )

    parser.add_argument(
        "--removeCertificateFiles",
        action="store_true",
        help="Remove the certificate files in current working directory (*.crt, *.pem).",
    )

    parser.add_argument(
        "--getCAcertPEM",
        action="store_true",
        help="Get cacert.pem from curl.se website to help find Root CA.",
    )

    global args

    args = parser.parse_args()


def loadRootCACertChain(__filename):
    """
    Load the Root CA Chain in a structured format.
    caRootStore = {
        "Root CA Name 1": "<PEM format1>",
        "Root CA Name 2": "<PEM format2>",
        ...
    }
    """
    previousLine = ""
    currentLine = ""

    caRootStore = {}
    try:
        with open(__filename, "r") as f_caCert:
            while True:
                previousLine = currentLine
                currentLine = f_caCert.readline()

                if not currentLine:
                    break

                if re.search("^\={5,}", currentLine):
                    """
                    This is where the Root CA certificate file begins.
                    Iterate through all the lines between
                    -----BEGIN CERTIFICATE-----
                    ...
                    -----END CERTIFICATE-----
                    """
                    rootCACert = ""
                    rootCAName = previousLine.strip()

                    while True:
                        caCertLine = f_caCert.readline()
                        if caCertLine.strip() != "-----END CERTIFICATE-----":
                            rootCACert += caCertLine
                        else:
                            rootCACert += "-----END CERTIFICATE-----\n"
                            break

                    caRootStore[rootCAName] = rootCACert

        print(f"Number of Root CA's loaded: {len(caRootStore)}")

        return caRootStore

    except FileNotFoundError:
        print(
            "Could not find cacert.pem file. Please run script with --getCAcertPEM to get the file from curl.se website."
        )
        sys.exit(1)


def removeCertificateFiles():
    """Removes all files that were generated by this script."""
    # Remove .crt files
    for iFile in glob.glob("*.crt"):
        print(f"Removing file {iFile}")
        os.remove(iFile)

    for iFile in glob.glob("*.pem"):
        print(f"Removing file {iFile}")
        os.remove(iFile)


def normalizeSubject(__subject):
    """Normalize the subject name to use for file name purposes."""
    normalizedName = __subject.split(",")

    # Iterate through all the elements of normalizedName, finding the CN= one.
    for item in normalizedName:
        isCommonName = item[:3]
        if isCommonName == "CN=":
            itemIndex = item.find("=")
            commonName = item[itemIndex + 1 :]
            break

    # Replace spaces with hyphens
    commonName = commonName.replace(" ", "-")

    # Remove wildcards
    commonName = commonName.replace("*.", "")

    # Make sure the filename string is lower case
    newNormalizedName = "".join(commonName).lower()

    # Return newNormalizedName
    return newNormalizedName


def getCertificate(__hostname, __port):
    """Retrieves the certificate from the website."""

    try:
        # Create the SSL context
        sslContext = ssl.create_default_context()

        with socket.create_connection((__hostname, __port)) as sock:
            with sslContext.wrap_socket(sock, server_hostname=__hostname) as sslSocket:
                # Get the certificate from the connection, convert it to PEM format.
                sslCertificate = ssl.DER_cert_to_PEM_cert(sslSocket.getpeercert(True))

        # Load the PEM formatted file.
        sslCertificate = x509.load_pem_x509_certificate(sslCertificate.encode("ascii"))

    except ConnectionRefusedError:
        print(f"Connection refused to {__hostname}:{__port}")
        sys.exit(1)

    # Return the sslCertificate object.
    return sslCertificate


def getCertificateFromUri(__uri):
    """Gets the certificate from a URI.
    By default, we're expecting to find nothing. Therefore certI = None.
    If we find something, we'll update certI accordingly.
    """
    certI = None

    # Attempt to get the aia from __uri
    aiaRequest = requests.get(__uri)

    # If response status code is 200
    if aiaRequest.status_code == 200:
        # Get the content and assign to aiaContent
        aiaContent = aiaRequest.content

        # Convert the certificate into PEM format.
        sslCertificate = ssl.DER_cert_to_PEM_cert(aiaContent)

        # Load the PEM formatted content using x509 module.
        certI = x509.load_pem_x509_certificate(sslCertificate.encode("ascii"))

    # Return certI back to the script.
    return certI


def returnCertAKI(__sslCertificate):
    """Returns the AKI of the certificate."""
    try:
        certAKI = __sslCertificate.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        )
    except x509.extensions.ExtensionNotFound:
        certAKI = None
    return certAKI


def returnCertSKI(__sslCertificate):
    """Returns the SKI of the certificate."""
    certSKI = __sslCertificate.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_KEY_IDENTIFIER
    )

    return certSKI


def returnCertAIA(__sslCertificate):
    """Returns the AIA of the certificate. If not defined, then return None."""
    try:
        certAIA = __sslCertificate.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )

    except x509.extensions.ExtensionNotFound:
        certAIA = None

    return certAIA


def returnCertAIAList(__sslCertificate):
    """Returns a list of AIA's defined in __sslCertificate."""
    aiaUriList = []

    # Iterate through all the extensions.
    for extension in __sslCertificate.extensions:
        certValue = extension.value

        # If the extension is x509.AuthorityInformationAccess) then lets get the caIssuers from the field.
        if isinstance(certValue, x509.AuthorityInformationAccess):
            dataAIA = [x for x in certValue or []]
            for item in dataAIA:
                if item.access_method._name == "caIssuers":
                    aiaUriList.append(item.access_location._value)

    # Return the aiaUriList back to the script.
    return aiaUriList


def walkTheChain(__sslCertificate, __depth):
    """
    Walk the length of the chain, fetching information from AIA
    along the way until AKI == SKI (i.e. we've found the Root CA.

    This is to prevent recursive loops. Usually there are only 4 certificates.
    If the maxDepth is too small (why?) adjust it at the beginning of the script.
    """

    if __depth <= maxDepth:
        # Retrive the AKI from the certificate.
        certAKI = returnCertAKI(__sslCertificate)
        # Retrieve the SKI from the certificate.
        certSKI = returnCertSKI(__sslCertificate)

        # Sometimes the AKI can be none. Lets handle this accordingly.
        if certAKI is not None:
            certAKIValue = certAKI._value.key_identifier
        else:
            certAKIValue = None

        # Get the value of the SKI from certSKI
        certSKIValue = certSKI._value.digest

        # Sometimes the AKI can be none. Lets handle this accordingly.
        if certAKIValue is not None:
            aiaUriList = returnCertAIAList(__sslCertificate)
            if aiaUriList != []:
                # Iterate through the aiaUriList list.
                for item in aiaUriList:
                    # get the certificate for the item element.
                    nextCert = getCertificateFromUri(item)

                    # If the certificate is not none (great), append it to the certChain, increase the __depth and run the walkTheChain subroutine again.
                    if nextCert is not None:
                        certChain.append(nextCert)
                        __depth += 1
                        walkTheChain(nextCert, __depth)
                    else:
                        print("Could not retrieve certificate.")
                        sys.exit(1)
            else:
                """Now we have to go on a hunt to find the root from a standard root store."""
                print("Certificate didn't have AIA...ruh roh.")

                # Load the Root CA Cert Chain.
                caRootStore = loadRootCACertChain("cacert.pem")

                # Assume we cannot find a Root CA
                rootCACN = None

                # Iterate through the caRootStore object.
                for rootCA in caRootStore:
                    try:
                        rootCACertificatePEM = caRootStore[rootCA]
                        rootCACertificate = x509.load_pem_x509_certificate(
                            rootCACertificatePEM.encode("ascii")
                        )
                        rootCASKI = returnCertSKI(rootCACertificate)
                        rootCASKI_Value = rootCASKI._value.digest
                        if rootCASKI_Value == certAKIValue:
                            rootCACN = rootCA
                            print(f"Root CA Found - {rootCACN}")
                            certChain.append(rootCACertificate)
                            break
                    except x509.extensions.ExtensionNotFound:
                        # Apparently some Root CA's don't have a SKI?
                        pass

                if rootCACN == None:
                    print("ERROR - Root CA NOT found.")
                    sys.exit(1)


def sendCertificateToFile(__filename, __sslCertificate):
    """Write the certificate in PEM format to file."""
    with open(__filename, "wb") as f_clientPublicKey:
        f_clientPublicKey.write(
            __sslCertificate.public_bytes(
                encoding=serialization.Encoding.PEM,
            )
        )


def writeChainToFile(__certificateChain):
    """Write all the elements in the chain to file."""
    # Iterate through all the elements in the chain.
    for counter, certificateItem in enumerate(__certificateChain):
        # Get the subject from the certificate.
        certSubject = certificateItem.subject.rfc4514_string()

        # Normalize the subject name
        normalizedSubject = normalizeSubject(certSubject)

        # Generate the certificate file name
        sslCertificateFilename = (
            str(len(__certificateChain) - 1 - counter)
            + "-"
            + normalizedSubject
            + ".crt"
        )

        # Send the certificate object to the sslCertificateFileName filename
        sendCertificateToFile(sslCertificateFilename, certificateItem)


def checkHostname(hostname):
    """Parse --hostname argument."""
    tmpLine = ""

    # If the ':' is in the hostname argument, then we'll assume it's meant to be a port following the ':'.
    if ":" in hostname:
        tmpLine = hostname.split(":")
        hostnameQuery = {"hostname": tmpLine[0], "port": int(tmpLine[1])}

    else:
        # If no ':' is found, then set default port 443.
        hostnameQuery = {"hostname": hostname, "port": 443}

    return hostnameQuery


def getCAcertPEM():
    """Retrieves the cacert.pem file from curl.se website."""
    cacertpemUri = "https://curl.se/ca/cacert.pem"

    cacertpem = requests.get(cacertpemUri)

    if cacertpem.status_code == 200:
        # Excellent! We have a cacert.pem file from curl.se website.
        with open("cacert.pem", "wb") as f_cacertpem:
            f_cacertpem.write(cacertpem.content)
    else:
        print(
            "Could not download cacert.pem. Please retrieve the file from the internet and manually upload to the current working directory."
        )


def main():
    """Main subroutine."""
    # Parse the arguments
    parseArguments()

    # If --removeCertificateFiles is passed, remove files and exit
    if args.removeCertificateFiles:
        removeCertificateFiles()
        sys.exit(0)

    if args.getCAcertPEM:
        getCAcertPEM()

    # Define the hostname to check.
    myHostname = checkHostname(args.hostname)

    # Get the website certificate object from myHostname["hostname"]:myHostname["port"]
    __websiteCertificate = getCertificate(myHostname["hostname"], myHostname["port"])

    if __websiteCertificate is not None:
        # Get the AIA from the __websiteCertificate object
        aia = returnCertAIA(__websiteCertificate)
        if aia is not None:
            # Extract the AIA URI list from the __websiteCertificate object.
            # aiaUriList = returnCertAIAList(__websiteCertificate)

            # Append the __websiteCertificate object to the certChain list.
            certChain.append(__websiteCertificate)

            # Now we walk the chain up until we get the Root CA.
            walkTheChain(__websiteCertificate, 1)

            # Write the certificate chain to individual files.
            writeChainToFile(certChain)
        else:
            print(
                "ERROR - I could not find AIA. Possible decryption taking place upstream?"
            )
            sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted")
        print()
        try:
            sys.exit(0)
        except SystemExit:
            os.exit(0)
