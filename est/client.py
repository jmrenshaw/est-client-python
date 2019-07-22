"""EST Client.

This is the first object to instantiate to interact with the API.
"""

import base64
import ssl
import subprocess

import OpenSSL.crypto

import asn1crypto.core

import est.errors
import est.request

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

class Client(object):
    """API client.

    Attributes:
        uri (str): URI prefix to use for requests.

        url_prefix (str): URL prefix to use for requests.  scheme://host:port
    """
    url_prefix = None
    username = None
    password = None
    implicit_trust_anchor_cert_path = None

    def __init__(self, host, port, implicit_trust_anchor_cert_path):
        """Initialize the client to interact with the EST server.

        Args:
            host (str): EST server hostname.

            port (int): EST server port number.

            implicit_trust_anchor_cert_path (str):
                EST server implicit trust anchor certificate path.
        """
        self.url_prefix = 'https://%s:%s/.well-known/est' % (host, port)
        self.implicit_trust_anchor_cert_path = implicit_trust_anchor_cert_path

    def cacerts(self):
        """EST /cacerts request.

        Args:
            None

        Returns:
            str.  CA certificates (PEM).

        Raises:
            est.errors.RequestError
        """
        url = self.url_prefix + '/cacerts'
        content = est.request.get(url,
            verify=self.implicit_trust_anchor_cert_path)

        pem = self.pkcs7_to_pem(content)

        return pem

    def simpleenroll(self, csr):
        """EST /simpleenroll request.

        Args:
            csr (str): Certificate signing request (PEM).

        Returns:
            str.  Signed certificate (PEM).

        Raises:
            est.errors.RequestError
        """
        url = self.url_prefix + '/simpleenroll'
        auth = (self.username, self.password)
        headers = {'Content-Type': 'application/pkcs10'}
        content = est.request.post(url, csr, auth=auth, headers=headers,
            verify=self.implicit_trust_anchor_cert_path)
        pem = self.pkcs7_to_pem(content)

        return pem

    def simplereenroll(self, csr, cert=False):
        """EST /simplereenroll request.

        Args:
            csr (str): Certificate signing request (PEM).

            cert (tuple): Client cert path and private key path.

        Returns:
            str.  Signed certificate (PEM).

        Raises:
            est.errors.RequestError
        """
        url = self.url_prefix + '/simplereenroll'
        auth = (self.username, self.password)
        headers = {'Content-Type': 'application/pkcs10'}
        content = est.request.post(url, csr, auth=auth, headers=headers,
            verify=self.implicit_trust_anchor_cert_path,
            cert=cert)
        pem = self.pkcs7_to_pem(content)

        return pem

    def csrattrs(self):
        """EST /csrattrs request.

        Returns:
            OrderedDict.  Example:
                OrderedDict([(u'0', u'1.3.6.1.1.1.1.22'),
                             (u'1', u'1.2.840.113549.1.9.1'),
                             (u'2', u'1.3.132.0.34'),
                             (u'3', u'2.16.840.1.101.3.4.2.2')])

        Raises:
            est.errors.RequestError
        """
        url = self.url_prefix + '/csrattrs'
        content = est.request.get(url,
            verify=self.implicit_trust_anchor_cert_path)

        parsed = asn1crypto.core.Sequence.load(content)
        return parsed.native

    def set_basic_auth(self, username, password):
        """Set up HTTP Basic authentication.

        Args:
            username (str).

            password (str).
        """
        self.username = username
        self.password = password

    def create_csr(self, common_name, country=None, state=None, city=None,
                   organization=None, organizational_unit=None,
                   email_address=None, subject_alt_name=None, algorithm='RSA', key_size=2048, curve_name=None):
        """
        Args:
            common_name (str).
            
            country (str).

            state (str).

            city (str).

            organization (str).

            organizational_unit (str).

            email_address (str).

            subject_alt_name (str).

            algorithm (str).
            
            key_size (int).
            
            curve_name (str).

        Returns:
            (str, str).  Tuple containing private key and certificate
            signing request (PEM).
        """
        if algorithm == 'RSA':
            key = OpenSSL.crypto.PKey()
            key.generate_key(OpenSSL.crypto.TYPE_RSA, key_size)

            req = OpenSSL.crypto.X509Req()
            req.get_subject().CN = common_name
            if country:
                req.get_subject().C = country
            if state:
                req.get_subject().ST = state
            if city:
                req.get_subject().L = city
            if organization:
                req.get_subject().O = organization
            if organizational_unit:
                req.get_subject().OU = organizational_unit
            if email_address:
                req.get_subject().emailAddress = email_address
            if subject_alt_name:
                altName = OpenSSL.crypto.X509Extension('subjectAltName', False, subject_alt_name)
                req.add_extensions([altName])
    
            req.set_pubkey(key)
            req.sign(key, 'sha256')
    
            private_key = OpenSSL.crypto.dump_privatekey(
                OpenSSL.crypto.FILETYPE_PEM, key)
    
            csr = OpenSSL.crypto.dump_certificate_request(
                       OpenSSL.crypto.FILETYPE_PEM, req)
            
        elif algorithm == 'EC':
            # Generate Elliptic Curve object
            ec_curve = ec.EllipticCurve
            ec_curve.name = curve_name
            
            ec_key = ec.generate_private_key(ec_curve, default_backend())
            
            # Serialize private key into PEM format to be returned.
            private_key = ec_key.private_bytes(encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Create the subject common name.
            subjectName = []
            subjectName.append(x509.NameAttribute(NameOID.COMMON_NAME, unicode(common_name)))           
            
            # Create list of x509 Name Attribute objects making up the subject name. 
            if country:
                subjectName.append(x509.NameAttribute(NameOID.COUNTRY_NAME, unicode(country)))
            if state:
                subjectName.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, unicode(state)))
            if city:
                subjectName.append(x509.NameAttribute(NameOID.LOCALITY_NAME, unicode(city)))
            if organization:
                subjectName.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, unicode(organization)))
            if organizational_unit:
                subjectName.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, unicode(organizational_unit)))
            if email_address:
                subjectName.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, unicode(email_address)))
            
            # Create subject alternative names.
            subjectAlternativeName = []
            if subject_alt_name:
                subjectAlternativeName.append(x509.DNSName(unicode(subject_alt_name)))        
            
            x509_csr = x509.CertificateSigningRequestBuilder().subject_name(
                x509.Name(subjectName)).add_extension(
                x509.SubjectAlternativeName(subjectAlternativeName),critical=False
                ).sign(ec_key, hashes.SHA256(), default_backend())
             
            csr = x509_csr.public_bytes(encoding=serialization.Encoding.PEM)
        else:
            raise est.errors.Error('Invalid algorithm, RSA or EC are supported')
        
        return private_key, csr

    def pkcs7_to_pem(self, pkcs7):
        inform = None
        for filetype in (OpenSSL.crypto.FILETYPE_PEM,
                         OpenSSL.crypto.FILETYPE_ASN1):
            try:
                OpenSSL.crypto.load_pkcs7_data(filetype, pkcs7)
                if filetype == OpenSSL.crypto.FILETYPE_PEM:
                    inform = 'PEM'
                else:
                    inform = 'DER'
                break
            except OpenSSL.crypto.Error:
                pass

        if not inform:
            raise est.errors.Error('Invalid PKCS7 data type')

        stdout, stderr = subprocess.Popen(
            ['openssl', 'pkcs7', '-inform', inform, '-outform', 'PEM',
             '-print_certs'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.PIPE
        ).communicate(pkcs7)

        return stdout.decode("utf-8")
