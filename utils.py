import datetime
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP


from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import base64
from cryptography.hazmat.primitives.asymmetric import padding
import os
import os.path as osp
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


def load_pubKeys(public_key_path):
    with open(public_key_path, "rb") as f:
        public = serialization.load_pem_public_key(
            f.read(), backend=default_backend()
        )
    return public

def load_priKeys(private_key_path):
    with open(private_key_path, "rb") as f:
        private = serialization.load_pem_private_key(
            f.read(), None, backend=default_backend()
        )
    return private

# Generate Key Pairs and Output to Spcified Folder
def generate_keypairs(root):
    key = RSA.generate(2048)
    private_key = key.export_key()
    write_file(root, "private.pem", private_key)

    public_key = key.publickey().export_key()
    write_file(root, root+".public.pem", public_key)

def load_cert(cert_path):
    cert_file = open(cert_path, 'rb')
    cert_data = cert_file.read()
    cert = x509.load_pem_x509_certificate(data=cert_data, backend=default_backend())
    return cert


def generate_cert(root, issuerName, subjectName, subPubKeyPath, issPriKeyPath):  

    subPubkey = load_pubKeys(subPubKeyPath)
    issPriKey = load_priKeys(issPriKeyPath)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Hong Kong"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Hong Kong"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, subjectName),
        x509.NameAttribute(NameOID.COMMON_NAME, subjectName+".com"),
    ])
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Hong Kong"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Hong Kong"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuerName),
        x509.NameAttribute(NameOID.COMMON_NAME, issuerName+".com"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        subPubkey
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    # Sign our certificate with our private key
    ).sign(issPriKey, hashes.SHA256())
    # Write our certificate out to disk.
    with open(osp.join(root, f"{subjectName}.cert.pem"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))



def verify_cert(cli_cert_path, ca_cert_path):
    cert_to_check = load_cert(cli_cert_path)
    ca_cert = load_cert(ca_cert_path)
    
    iss_pubKey = ca_cert.public_key()
    iss_pubKey.verify(
        cert_to_check.signature,
        cert_to_check.tbs_certificate_bytes,
        # Depends on the algorithm used to create the certificate
        padding.PKCS1v15(),
        cert_to_check.signature_hash_algorithm,
    )


    

# Generate Session Key for Symmectric Encryption
def generate_session_key(root, sid):
    session_key = get_random_bytes(16)

    sesKey_path = osp.join(root,sid, f'{sid}.session_key.pem')
    with open(sesKey_path, "wb") as f:
        f.write(session_key)
    return session_key

def export_pubKey_from_cert(root, sid):
    cert_path = osp.join(root,sid, f'{sid}.cert.pem')
    # print(cert_path)
    cert = load_cert(cert_path)
    stu_pubKey = cert.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo)

    pubKey_path = osp.join(root,sid, f'{sid}.public.pem')
    with open(pubKey_path, "wb") as f:
        f.write(stu_pubKey)




def gen_session_key_and_RSAEnc_by_certkey(root, sid):
    

    plaintext = generate_session_key(root, sid)   
    export_pubKey_from_cert(root, sid)
    stu_pubKey = RSA.import_key(open(osp.join(root, sid, f'{sid}.public.pem')).read())

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(stu_pubKey)
    enc_session_key = cipher_rsa.encrypt(plaintext)
    enc_session_key_path = osp.join(root, sid, f'{sid}.enc_session_key.pem')
    with open(enc_session_key_path, "wb") as file_out:
        file_out.write(enc_session_key)
    # print(enc_session_key)
    return plaintext

def RSA_decrypt_session_key(root):
# def RSA_decrypt_session_key(root, enc_filepath):
    enc_filepath = osp.join(root, f'{root}.enc_session_key.pem')
    ciphertext = open(enc_filepath,'rb').read()
    # print(ciphertext)
    stu_priKey = RSA.import_key(open(osp.join(root, 'private.pem')).read())

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(stu_priKey)
    session_key = cipher_rsa.decrypt(ciphertext)
    # print(session_key)

    session_key_path = osp.join(root, f'{root}.session_key.pem')
    with open(session_key_path, "wb") as file_out:
        file_out.write(session_key)
    return session_key

def AES_encrypt_and_digest(data, key, enc_filepath):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    file_out = open(enc_filepath, "wb")
    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
    file_out.close()


def AES_decrypt_and_verify(enc_filepath, key):
    file_in = open(enc_filepath, "rb")
    nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]
    file_in.close()

    # let's assume that the key is somehow available again
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data
 
def print_base64(filepath):
    with open(filepath, "rb") as f:
        encodedZip = base64.b64encode(f.read())
        print(encodedZip.decode())

def write_file(dir, fillname, content):
    if not os.path.exists(dir):
        os.makedirs(dir)
    with open(dir+"/"+fillname, "wb") as file_out:
        file_out.write(content)
    file_out.close()


if '__main__' == __name__:
    # generate_keypairs("cuhk")
    # generate_keypairs("1")
    
    # root='cuhk'


    issuerName = 'cuhk'
    subjectName = '1'
    generate_keypairs('cuhk')

    # verify_cert("cuhk/1.cert", "cuhk/cuhk.cert")

    # generate_cert(issuerName, subjectName, osp.join(subjectName, "public.pem"), osp.join(issuerName, "private.pem"))

    # generate_cert(root, "1/public.pem", osp.join(root, "private.pem"))
    # generate_session_key("blackboard","1")
    # print_base64("cuhk/public.pem")
    # pri, pub = load_keys("cuhk/public.pem", "cuhk/private.pem")
    # print(pri)
    # print(pub)

    # session_key1 = generate_session_key("blackboard",root)
    # print(session_key1)
    # pubKey = RSA.import_key(open("1/public.pem").read())
    # RSA_encrypt_session_key("1/public.pem", session_key1, "encrypted.bin")
    
    # priKey = RSA.import_key(open("1/private.pem").read())
    # RSA_decrypt_session_key(priKey, "encrypted.bin", "session_key.bin")
    # session_key = get_random_bytes(16)
    # AES_encrypt_and_digest("11111".encode("utf-8"), session_key, "aes-enc.bin")
    # data = AES_decrypt_and_verify("aes-enc.bin", session_key)
    # print(data)


    # generate_session_key('blackboard', "1822")
    # export_pubKey_from_cert('blackboard', "1822")
    # gen_session_key_and_RSAEnc_by_certkey('blackboard', "1822")
    # RSA_decrypt_session_key("1822", "blackboard/1822/1822.enc_session_key.pem") #后面路径写死，仅仅用于测试



