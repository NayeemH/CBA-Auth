import os
import ssl

from flask import Flask, request

app = Flask(__name__)

@app.route('/api')
def api():
    # Authenticate the client's certificate
    cert = request.environ['ssl_client_cert']
    # Verify the certificate using the self-signed certificate
    ca_cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM,
        open(os.path.abspath('certificate.pem'), 'rb').read()
    )
    try:
        OpenSSL.crypto.verify(ca_cert, cert, None, 'sha256')
    except OpenSSL.crypto.Error:
        return 'Unauthorized', 401
    # Add your own code here to perform additional validation checks
    return 'Hello, world!'

if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_cert_chain(os.path.abspath('certificate.pem'), os.path.abspath('private_key.pem'))
    context.verify_mode = ssl.CERT_REQUIRED
    app.run(host='0.0.0.0', port=5000, ssl_context=context)
