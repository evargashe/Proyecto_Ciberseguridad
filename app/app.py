from flask import Flask, render_template, request
from urllib.parse import urlparse
from flask import flash
from werkzeug.utils import secure_filename

import re
import ssl, os
import certifi

from oscrypto import tls
from certvalidator import CertificateValidator, errors


import os
import re
from oscrypto import tls
from certvalidator import CertificateValidator, errors
from flask_wtf.file import FileField
from asn1crypto import pem
from asn1crypto.x509 import Certificate



app=Flask(__name__)
app.secret_key = "super secret key"

#Route
@app.route('/')
def index():
    return render_template('index.html')

def isValidURL(str):
    regex = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    if (str == None):
        return False
    if(re.search(regex, str)):
        return True
    else:
        return False

#get certificate digital ssl

def certificatessl(host):

    port = "443"
    address = (host, port)
    # Retrieve the server certificate and validate
    cert = ssl.get_server_certificate(address, ca_certs=os.path.relpath(certifi.where()))
    return cert

#Certificate root
def certificateRoot(url):
    port = "443"
    session = tls.TLSSession(manual_validation=True)
    connection = tls.TLSSocket(url , 443 , session=session)
    #try:
    validator = CertificateValidator(connection.certificate, connection.intermediates)
    result = validator.validate_tls(connection.hostname)
    return result



#R5: Se verifica si el certificado raíz de la cadena de certificación se encuentra en el repositorio del: 
#(i) Microsoft Edge, (ii) Mozilla Firefox y (iii) Google Chrome.


CERT = {}

def load(filename=None):
    if filename is None:
        return []
    list_cert = []
    with open(f'./TrustStore/{filename}', 'rb') as f:
        for _, _, der_bytes in pem.unarmor(f.read(), multiple=True):
            list_cert.append(Certificate.load(der_bytes))
    return list_cert

def loadCertificates():

    if CERT.get('has'):
        return
    CERT.update({
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

    for mozilla_certificate in CERT.get('mozillaCertificates'):
        certificates = mozilla_certificate.key_identifier_value
        if root == certificates:
            dataCertificate.update({'bool_mozilla': True})

    for chrome_certificate in CERT.get('chromeCertificates'):
        certificates = chrome_certificate.key_identifier_value
        if root == certificates:
            dataCertificate.update({'bool_chrome': True})

    for edge_certificate in CERT.get('edgeCertificates'):
        certificates = edge_certificate.key_identifier_value
        if root == certificates:
            dataCertificate.update({'bool_edge': True})

    dataCertificate['name'] = root_certificate.subject.human_friendly
    return dataCertificate



from flask import redirect

#validate URL
@app.route('/validate', methods=['POST','GET'])
def validate():
    if request.method == 'POST':
            auxurl = request.form['url']
            url = urlparse(auxurl).netloc
            si = 'url is valid'
            no = 'url isnot valid'
            if (auxurl == ''):
                flash("Empty field enter a url","danger")
                return redirect('/')

            elif(isValidURL(auxurl) == True):
                cert = certificatessl(url)
                root = certificateRoot(url)
                verificar = verificateReporitory(url)
                flash("the url was validated successfully","success")
                return render_template(
                'validate.html', sn = si, url = url ,cert = cert, 
                root1 = hex(root.__getitem__(0).serial_number), root2 = hex(root.__getitem__(1).serial_number) , 
                root3 = hex(root.__getitem__(2).serial_number), 
                verificar = verificar)
                """ verificar = verificar.get('bool_mozilla') """
            else:
                flash("the url was not validated correctly","error")
                return render_template('validate.html', sn = no)
        
@app.route('/TrustStoreChrome/')
def TrustStoreChrome():
    loadCertificates()
    certificate = CERT.get('chromeCertificates')
    return render_template('TrustStoreChrome.html', certificate = certificate)


@app.route('/TrustStoreMozilla/')
def TrustStoreMozilla():
    loadCertificates()
    certificate = CERT.get('mozillaCertificates')
    return render_template('TrustStoreMozilla.html',certificate = certificate)


@app.route('/TrustStoreEdge/')
def TrustStoreEdge():
    loadCertificates()
    certificate = CERT.get('edgeCertificates')
    return render_template('TrustStoreEdge.html',certificate = certificate)
        

UPLOAD_FOLDER = './TrustStore'
ALLOWED_EXTENSIONS = {'txt'}


app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class Form():
    file= FileField()
@app.route('/uploadFile', methods=['POST','GET'])
def uploadFile():
    f = request.files['file']
    urls = []
    lista = []
    if  f.content_type == 'text/plain':
        f.save(os.path.join(os.path.abspath(os.path.dirname(__file__)),secure_filename(f.filename)))
        with open(f.filename,'r') as file:
            for line in file:
                if isValidURL(line) == True:
                    url = urlparse(line).netloc
                    cert = certificatessl(url)
                    root = certificateRoot(url)
                    verificar = verificateReporitory(url)
                    lista.append(url)
                    lista.append(cert)
                    lista.append(hex(root.__getitem__(0).serial_number))
                    lista.append(hex(root.__getitem__(1).serial_number))
                    lista.append(hex(root.__getitem__(2).serial_number))
                    lista.append(verificar)
                    urls.append(line)
        return render_template('uploadFile.html', s = urls, lista=lista)
    elif f == '':
        flash('Ingrese un texto plano','texto')
        return redirect('/')
    else:
        flash('El archivo no es un archivo de texto plano .txt' , 'notexto')
        return redirect('/')
 
if __name__ == '__main__':
    app.run(debug=True, port=5000)