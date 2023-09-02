import socket
import os
import os.path as osp
import sys
import struct
import threading
import re
import argparse
from utils import generate_keypairs, generate_cert, generate_cert

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
        conn.send('Hi, Welcome to the server!'.encode('utf-8'))
        t = threading.Thread(target=run, args=(conn, root))
        t.start()
def receiveFile(conn, root):
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
        # conn.close()
        break

def run(conn, root):
    filename = receiveFile(conn, root)
    sid = os.path.basename(os.path.dirname(filename))

    generate_cert(
        root=osp.join(root, sid),
        issuerName='cuhk', 
        subjectName=sid, 
        subPubKeyPath=filename, 
        issPriKeyPath=osp.join(root, 'private.pem'))
    cert_path = osp.join(root, sid, f"{sid}.cert.pem")
    print(f'Finish generate Cert for sid: {sid}')
    sendFile(conn, cert_path)
    print(f'Finish send Cert to sid: {sid}')
    conn.close()
    

if __name__ == '__main__':
    os.makedirs('cuhk', exist_ok=True)
    root = 'cuhk'
    generate_keypairs(root='cuhk')
    generate_cert(
        root=root, 
        issuerName='cuhk', 
        subjectName='cuhk', 
        subPubKeyPath=osp.join(root, 'cuhk.public.pem'), 
        issPriKeyPath=osp.join(root, 'private.pem'))

    print('Finish generate keypairs and CA self_signed Cert')

    clientIP = '127.0.0.1'
    serverIP = '127.0.0.1'
    serverPort = 12345


    socket_service(serverIP, serverPort, root)
