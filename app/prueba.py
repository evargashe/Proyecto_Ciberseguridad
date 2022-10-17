from oscrypto import tls
from certvalidator import CertificateValidator, errors

session = tls.TLSSession(manual_validation=True)
connection = tls.TLSSocket('meet.google.com', 443 , session=session)

try:
    validator = CertificateValidator(connection.certificate, connection.intermediates)
    result = validator.validate_tls(connection.hostname)
    cert_1 = result.__getitem__(0)
    cert_2 = result.__getitem__(1)
    cert_3 = result.__getitem__(2)
    print(hex(result.__getitem__(1).serial_number))
except (errors.PathValidationError):
    print("The certificate did not match hostname")



""" import pem
from cryptography import x509


certs = pem.parse_file("./TrustStore/ChromeRootsPEM.txt") """
""" import os
import re
from oscrypto import tls
from certvalidator import CertificateValidator, errors
from flask_wtf.file import FileField
from asn1crypto import pem
from asn1crypto.x509 import Certificate



CERTIFICATES = {}

def load(filename=None):
    if filename is None:
        return []
    list_cert = []
    with open(f'./TrustStore/{filename}', 'rb') as f:
        for _, _, der_bytes in pem.unarmor(f.read(), multiple=True):
            list_cert.append(Certificate.load(der_bytes))

    return list_cert

def loadCertificates():

    if CERTIFICATES.get('has'):
        return
    CERTIFICATES.update({
        'mozillaCertificates': load('MozillaRootsPEM.txt'),
        'chromeCertificates': load('ChromeRootsPEM.txt'),
        'edgeCertificates': load('EdgeRootsPEM.txt'),
        'has': True,
    })

def verificateReporitory(url):
    dataCertificate = dict(
        bool_mozilla=False,
        bool_chrome=False,
        bool_edge=False,
        mozillaTrustLevel=1,
        chromeTrustLevel=1,
        edgeTrustLevel=1,
    )
    try:
        connection = tls.TLSSocket(url, 443, session=tls.TLSSession(manual_validation=True))
    except Exception as e:
        return 'has not certificate digital'
    
    validator = CertificateValidator(connection.certificate, connection.intermediates)

    certification_chain = validator.validate_tls(connection.hostname)
    root_certificate = certification_chain[0]
    root = root_certificate.key_identifier_value
    loadCertificates()

    for mozilla_certificate in CERTIFICATES.get('mozillaCertificates'):
        certificates = mozilla_certificate.key_identifier_value
        if root == certificates:
            dataCertificate.update({'bool_mozilla': True})

    for chrome_certificate in CERTIFICATES.get('chromeCertificates'):
        certificates = chrome_certificate.key_identifier_value
        if root == certificates:
            dataCertificate.update({'bool_chrome': True})

    for edge_certificate in CERTIFICATES.get('edgeCertificates'):
        certificates = edge_certificate.key_identifier_value
        if root == certificates:
            dataCertificate.update({'bool_edge': True})

    #dataCertificate['name'] = root_certificate.subject.human_friendly
    return dataCertificate

result = verificateReporitory('meet.google.com')
print(result)

 """


""" from urllib.parse import urlparse

domain = urlparse('https://www.google.com/foo/bar').netloc
print(domain) # --> www.example.test
 """
""" import re
url = 'https://www.youtube.com/'
host = re.search(r'https://([^/?:]*)', url).group(1)
print(host) """

""" 
import os
import re
from oscrypto import tls
from certvalidator import CertificateValidator, errors
from flask_wtf.file import FileField
from asn1crypto import pem
from asn1crypto.x509 import Certificate

def file_to_certificate_object_list(filename=None):
    if filename is None:
        return []
    certificates_list = []
    with open(f'./TrustStore/{filename}', 'rb') as f:
        for _, _, der_bytes in pem.unarmor(f.read(), multiple=True):
            certificates_list.append(Certificate.load(der_bytes))

    return certificates_list

CERTIFICATES = {}
CERTIFICATES.update({
        'mozilla_certificates': file_to_certificate_object_list('MozillaRootsPEM.txt'),
        'chrome_certificates': file_to_certificate_object_list('ChromeRootsPEM.txt'),
        'edge_certificates': file_to_certificate_object_list(),
        'has_certificates': True,
    })

c = CERTIFICATES.get('chrome_certificates')

for i in c:
        try:
            print("-"*10)
            print(i.subject.human_friendly)
            print(i.serial_number)
            print(i.not_valid_before, i.not_valid_after)
            print(i.public_key.algorithm, i.public_key.bit_size)
            print(i.sha1_fingerprint)
            print(i.key_usage_value.native)
        except Exception as e:
            print("ERROR") """
    