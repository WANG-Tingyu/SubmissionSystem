import socket
import os
import os.path as osp
import sys
import struct
import threading
import re
import argparse
from cryptography.exceptions import InvalidSignature
from utils import verify_cert, gen_session_key_and_RSAEnc_by_certkey, AES_decrypt_and_verify, AES_encrypt_and_digest

def socket_service(serverIP, serverPort, root):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((serverIP, serverPort))
        s.listen(10)
    except socket.error as msg:
        print(msg)
        sys.exit(1)
    print('Waiting connection...')

    while 1:
        conn, addr = s.accept()
        print(f'Accept new connection from {addr}')
        conn.send('Hi, Welcome to the BlackBoard!'.encode('utf-8'))
        t = threading.Thread(target=run, args=(conn, root))
        t.start()

def sendMsg(conn, msg):
    conn.send(msg.encode('utf-8'))
    
def receiveMsg(conn):
    print(conn.recv(1024).decode('utf-8'))

def receiveFile(conn, root):
    new_filename = 'exit' ## used to close current thread safely
    while 1:
        fileinfo_size = struct.calcsize('256sl')
        buf = conn.recv(fileinfo_size)
        if buf:
            filename, filesize = struct.unpack('256sl', buf)
            # fn = filename
            fn = filename.decode('utf-8').strip('\00')
            os.makedirs(os.path.join(f'./{root}', fn.split('.')[0]), exist_ok=True)
            new_filename = os.path.join(f'./{root}', fn.split('.')[0], fn)
            # print('file new name is {0}, filesize if {1}'.format(new_filename,
            #                                                      filesize))

            recvd_size = 0  
            fp = open(new_filename, 'wb')
            # print('start receiving...')

            while not recvd_size == filesize:
                if filesize - recvd_size > 1024:
                    data = conn.recv(1024)
                    recvd_size += len(data)
                else:
                    data = conn.recv(filesize - recvd_size)
                    recvd_size = filesize
                fp.write(data)
            fp.close()
            # print('end receive...')
        # conn.close()
        break
    return new_filename

def sendFile(conn, filepath):
    while 1:
        if os.path.isfile(filepath):
            fileinfo_size = struct.calcsize('256sl')
            fhead = struct.pack('256sl', os.path.basename(filepath).encode('utf-8'),
                                os.stat(filepath).st_size)
            conn.send(fhead)
            # print('client filepath: {0}'.format(filepath))

            fp = open(filepath, 'rb')
            while 1:
                data = fp.read(1024)
                if not data:
                    # print('{0} file send over...'.format(filepath))
                    break
                conn.send(data)
        break
def communication(conn, root, session_key):
    while 1:
        filename = receiveFile(conn, root)
        if filename == 'exit':
            print('Close one connection')
            break
        ### decrypt the msg file
        decryptMsg = AES_decrypt_and_verify(filename, session_key)
        decryptMsg = decryptMsg.decode('utf-8')
        ###
        sid = os.path.basename(os.path.dirname(filename))
        print(f'{sid}: {decryptMsg}')


def run(conn, root):
    stu_cert_path = receiveFile(conn, root)
    sid = os.path.basename(os.path.dirname(stu_cert_path))
    print(f'Received Certificant from sid: {sid}')
    valid = True
    try:
        verify_cert(cli_cert_path=stu_cert_path, ca_cert_path=osp.join('cuhk', 'cuhk.cert.pem')) ### be relaced by verify the cert and encrpypt
    except InvalidSignature:
        print('Certificate is invalid')
        valid = False
    if valid:
        print('Certificate is valid')
        sendMsg(conn, msg='Certificate is valid')
    else:
        sendMsg(conn, msg='Certificate is invalid')
    session_key = gen_session_key_and_RSAEnc_by_certkey(root, sid)
    print('Generated Session key')
    sendFile(conn, osp.join(root, sid, f'{sid}.enc_session_key.pem'))
    print('Sent out Session key')
    communication(conn, root, session_key)
    conn.close()
    

if __name__ == '__main__':
    os.makedirs('blackboard', exist_ok=True)
    root = 'blackboard'
    clientIP = '127.0.0.1'
    serverIP = '127.0.0.1'
    serverPort = 12346

    # 1. gererate key pairs 2.generate ca cert
    socket_service(serverIP, serverPort, root)