#!/usr/bin/python3

""" Android TV Remote

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.
"""

__authors__ = ["Rik", "Mario"]
__contact__ = "https://github.com/rvk01"
__copyright__ = "Copyright 2023"
__license__ = "GPLv3"
__deprecated__ = False
__status__ = "Development"
__date__ = "2023-02-24"
__version__ = "0.0.2"

# ----------------------------------------------
#
# ----------------------------------------------
import logging
import sys
import os
import datetime, time
import select, socket, ssl
import threading
import queue
import hashlib
import requests
import urllib.parse
import pairingmessage_pb2
import remotemessage_pb2
#from lxml import etree
from pysimplesoap.simplexml import SimpleXMLElement
from OpenSSL.crypto import load_certificate
from OpenSSL.crypto import FILETYPE_PEM
from asn1crypto.x509 import Certificate
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

dir_path = os.path.dirname(os.path.realpath(__file__))

# ----------------------------------------------
# Certificate automatically in same directory as script
# ----------------------------------------------
CERT_FILE=dir_path + "/client.pem"
DEVICE_FILE=dir_path + "/server.txt"
INDEX_FILE=dir_path + "/index.html"
INDEX_FILE1=dir_path + "/index1.html"
INDEX_FILE2=dir_path + "/index2.html"
INDEX_FILE3=dir_path + "/index3.html"

# ----------------------------------------------
#
# ----------------------------------------------
log = logging.getLogger("atvr")
logging.basicConfig()
log.setLevel(logging.INFO)

def discover(timeout=1.0, retries=1, want_usn=None):
    locations = []
    group = ('239.255.255.250', 1900)
    service = 'urn:dial-multiscreen-org:service:dial:1'
    #service = 'ssdp:all'
    message = '\r\n'.join(['M-SEARCH * HTTP/1.1', 'HOST: {group[0]}:{group[1]}',
        'MAN: "ssdp:discover"', 'ST: {st}', 'MX: 3', '', '']).format(group=group, st=service)
    socket.setdefaulttimeout(timeout)
    for _ in range(retries):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.sendto(message.encode('utf-8'), group)
        while True:
            try:
                response = sock.recv(2048).decode('utf-8')
                location=None
                usn=None
                for line in response.split('\r\n'):
                    if line.startswith('LOCATION: '): location = line.split(' ')[1].strip()
                    if line.startswith('USN: '): usn = line.split(' ')[1].strip()
                usn = usn.split(':')[1].strip()
                if not location is None and (want_usn is None or want_usn==usn):
                    locations.append((location,usn))
                    if want_usn==usn: break
            except socket.timeout:
                break
    locations = set({i: j for i,j in reversed(locations)}.items())
    return  locations

def msg2str(arr):
    v = ''.join((format(x, '1d')+' ') for x in arr)
    return v

def enumvalid(str, enum):
    try:
        return enum.Value(str)
    except ValueError as e: # Above assignment throws a ValueError, caught here
        return None

def getdeviceip(want_usn):
    devices = discover(5.0,1,want_usn)
    if len(devices) == 0: return (None, None)
    for location, usn in devices:
        o = urllib.parse.urlsplit(location)
        r = requests.get(location)
        d = SimpleXMLElement(r.text)
        x = str(next(d.friendlyName()))
        return(o.hostname, x)

# ----------------------------------------------
#
# ----------------------------------------------
def generate_selfsigned_cert(hostname, ip_addresses=None, key=None):
    if key is None: key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend(), )
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    alt_names = [x509.DNSName(hostname)]
    san = x509.SubjectAlternativeName(alt_names)
    basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=10*365))
        .add_extension(basic_contraints, False)
        .add_extension(san, False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


# ----------------------------------------------
#
# ----------------------------------------------
class AndroidRemote:

    def __init__(self, host_address):
        self.host = host_address

    def connect(self, pairing = False):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ssl_sock = ssl.wrap_socket(self.sock, keyfile=CERT_FILE, certfile=CERT_FILE, do_handshake_on_connect=True)
        self.ssl_sock.connect((self.host, 6467 if pairing else 6466))
        self.sock.close() # original not needed anymore
        log.info('connecting to ' + self.host + (' 6467 pairing port' if pairing else ' 6466 remote port'))

    def disconnect(self):
        try: # only exception we handle here because it doesn't matter
            self.ssl_sock.shutdown(socket.SHUT_RDWR)
            self.ssl_sock.close()
        except Exception as x:
            log.info(x)
        log.info('disconnected')

    def send_message(self, msg):
        m = bytearray(msg.SerializeToString())
        log.debug('---> ' + msg2str(m))
        log.debug('---> ' + str(m))
        self.ssl_sock.send((len(m)).to_bytes(1, byteorder='big'))
        self.ssl_sock.send(m)

    def start_pairing(self):

        buffer=bytearray()

        p=pairingmessage_pb2.PairingMessage()
        p.pairing_request.service_name = 'com.atvr.test'
        p.pairing_request.client_name = 'atvr'
        p.status = pairingmessage_pb2.PairingMessage.STATUS_OK
        p.protocol_version = 2
        self.send_message(p)

        while True:

            data = self.ssl_sock.recv(1024)
            buffer = buffer + data

            if (len(buffer) > 1) and (buffer[0] <= len(buffer) - 1):

                log.debug('recv ' + str(buffer))
                m = pairingmessage_pb2.PairingMessage()
                m.ParseFromString(bytes(buffer[1:]))
                log.debug(m)

                if m.HasField('pairing_request_ack'):
                    log.info('receive pairing response')
                    log.info('send options')
                    p=pairingmessage_pb2.PairingMessage()
                    p.pairing_option.preferred_role = pairingmessage_pb2.ROLE_TYPE_INPUT
                    p.pairing_option.input_encodings.add()
                    p.pairing_option.input_encodings[0].type = pairingmessage_pb2.PairingEncoding.ENCODING_TYPE_HEXADECIMAL
                    p.pairing_option.input_encodings[0].symbol_length = 6
                    p.status = pairingmessage_pb2.PairingMessage.STATUS_OK
                    p.protocol_version = 2
                    self.send_message(p)

                if m.HasField('pairing_option'):
                    log.info('receive option response')
                    log.info('Send config');
                    p=pairingmessage_pb2.PairingMessage()
                    p.pairing_configuration.client_role = pairingmessage_pb2.ROLE_TYPE_INPUT
                    p.pairing_configuration.encoding.type = pairingmessage_pb2.PairingEncoding.ENCODING_TYPE_HEXADECIMAL
                    p.pairing_configuration.encoding.symbol_length = 6
                    p.status = pairingmessage_pb2.PairingMessage.STATUS_OK
                    p.protocol_version = 2
                    self.send_message(p)

                if m.HasField('pairing_configuration_ack'):
                    log.info('receive config response')

                    try:
                        print('')
                        print('Enter last 4 digits of the TV code (whole code is OK, and not case sensitive.')
                        print('')
                        input_code = input('Enter code? ')
                        print('')
                    except KeyboardInterrupt:
                        print('')
                        print('KEYBOARD INTERRUPT')
                        return False

                    with open(CERT_FILE, 'rb') as fp: cert = load_certificate(FILETYPE_PEM, fp.read())
                    server_cert = Certificate.load(self.ssl_sock.getpeercert(True))
                    client_modulus = cert.get_pubkey().to_cryptography_key().public_numbers().n
                    client_exponent = cert.get_pubkey().to_cryptography_key().public_numbers().e
                    server_modulus = server_cert.public_key.native["public_key"]["modulus"]
                    server_exponent = server_cert.public_key.native["public_key"]["public_exponent"]

                    # all items in hex format
                    client_mod = '{:X}'.format(client_modulus)
                    server_mod = '{:X}'.format(server_modulus)
                    client_exp = "010001"
                    server_exp = "010001"

                    # we just need the last 4 digits
                    code=input_code[-4:]

                    h = hashlib.sha256()
                    h.update(bytes.fromhex(client_mod))
                    h.update(bytes.fromhex(client_exp))
                    h.update(bytes.fromhex(server_mod))
                    h.update(bytes.fromhex(server_exp))
                    h.update(bytes.fromhex(code))
                    hash_result = h.digest()

                    log.info('Sending TV secret code');
                    message = bytearray(hash_result)

                    p=pairingmessage_pb2.PairingMessage()
                    p.pairing_secret.secret = bytes(message)
                    p.status = pairingmessage_pb2.PairingMessage.STATUS_OK
                    p.protocol_version = 2
                    self.send_message(p)

                if (m.status == pairingmessage_pb2.PairingMessage.STATUS_BAD_SECRET):
                    log.info('receive wrong TV secret code')
                    log.info('pairing unsuccesful')
                    return False

                if m.HasField('pairing_secret_ack'):
                    hostname=socket.gethostname()
                    ipaddr=socket.gethostbyname(hostname)
                    log.info('receive correct TV secret code')
                    log.info('pairing success');
                    log.info('');
                    log.info('You can now choose to run the program as daemon/service');
                    log.info('You can exit with CTRL+C and browse to http://%s/index or /index0' % ipaddr);
                    log.info('');
                    return True

                log.debug('rmov ' + str(buffer))
                del buffer[0:buffer[0] + 1] # remove message from buffer
                log.debug('rest ' + str(buffer))

    def check_remote(self):

        buffer=bytearray()
        cnt=0
        connected=False

        while True:

            global stop_threads
            if stop_threads:
                log.info('STOP REMOTE THREAD')
                break

            # we receive commands via queue, execute them
            if connected and not queue.empty():
              data = queue.get()
              if data=='STOP':
                  # test exception to see if thread can restart itself
                  raise Exception("Force (and test) exception to end remote thread")
              self.dostring('KEYCODE_' + data)


            socket_list = [self.ssl_sock]
            read_sockets, write_sockets, error_sockets = select.select(socket_list , [], [], 0)
            data = None
            for sock in read_sockets:
                if sock == self.ssl_sock:
                    data = self.ssl_sock.recv(1024)
            if data == None: continue

            buffer = buffer + data

            if (len(buffer) > 1) and (buffer[0] <= len(buffer) - 1):

                log.debug('recv ' + str(buffer))
                m = remotemessage_pb2.RemoteMessage()
                m.ParseFromString(bytes(buffer[1:]))
                log.debug(m)

                if m.HasField('remote_ping_request'):
                    # less chatty PING/PONG
                    cnt+=1;
                    if cnt==10:
                        log.info('PING')
                        log.info('PONG')
                        cnt=0
                    p = remotemessage_pb2.RemoteMessage()
                    p.remote_ping_response.val1 = 1
                    self.send_message(p)

                if m.HasField('remote_configure'):
                    log.info('receive config')
                    log.info('sending config');

                    p = remotemessage_pb2.RemoteMessage()
                    p.remote_configure.code1 = 622
                    p.remote_configure.device_info.model = 'atvr'
                    p.remote_configure.device_info.vendor = 'rvk01'
                    p.remote_configure.device_info.unknown1 = 1
                    p.remote_configure.device_info.unknown2 = '1'
                    p.remote_configure.device_info.package_name = 'atvr'
                    p.remote_configure.device_info.app_version = '0.0.2'
                    self.send_message(p)


                if m.HasField('remote_set_active'):
                    log.info('receive set active')
                    log.info('sending set active');

                    p = remotemessage_pb2.RemoteMessage()
                    p.remote_set_active.active = 622
                    self.send_message(p)


                if m.HasField('remote_start'):
                    log.info('WE HAVE A CONNECTION')
                    connected=True

                log.debug('rmov ' + str(buffer))
                del buffer[0:buffer[0] + 1] # remove message from buffer


    def sendkey(self, KEY):
        p = remotemessage_pb2.RemoteMessage()
        p.remote_key_inject.key_code = KEY
        p.remote_key_inject.direction = remotemessage_pb2.START_LONG
        self.send_message(p)
        p.remote_key_inject.direction = remotemessage_pb2.END_LONG
        self.send_message(p)

    def sendkey2(self, KEY):
        p = remotemessage_pb2.RemoteMessage()
        p.remote_key_inject.key_code = KEY
        p.remote_key_inject.direction = remotemessage_pb2.SHORT
        self.send_message(p)

    def dostring(self, cmd):
        if not enumvalid(cmd, remotemessage_pb2.RemoteKeyCode): return
        i=remotemessage_pb2.RemoteKeyCode.Value(cmd)
        log.info('SendKey %s' % cmd)
        self.sendkey(i)

# ----------------------------------------------
# check server.txt and if not exists choose a device
# ----------------------------------------------
def check_device_and_choose():
    if not os.path.isfile(DEVICE_FILE):
        print("Android TV Remote - Choosing device - (collecting...)")
        print()
        devices = discover(5.0,1)
        #for device, usn in devices:
        idx=0
        devices=list(devices)
        for location, usn in devices:
             idx+=1
             o = urllib.parse.urlsplit(location)
             r = requests.get(location)
             d = SimpleXMLElement(r.text)
             x = str(next(d.friendlyName()))
             print('{0:>2}) {1: <16} {2: <40} {3}'.format(idx,o.hostname, x, usn))
        print()
        while True:
            try:
                x = input("Enter which device you want to use: ")
                usn=devices[int(x)-1][1]
                break
            except KeyboardInterrupt:
                print('KEYBOARD INTERRUPT')
                sys.exit()
            except:
                print('Try again')
        with open(DEVICE_FILE, "wt") as f: f.write(usn)
        print()

# ----------------------------------------------
# check if certificate exists, create and pair with tv
# ----------------------------------------------
def check_certificate_and_pair():
    # We always need a certificate, create one if it does not exists
    if not os.path.isfile(CERT_FILE):
        log.info("Generating certificate")
        cert, key = generate_selfsigned_cert("atvr")
        with open(CERT_FILE, "wt") as f: f.write(cert.decode("utf-8") + key.decode("utf-8"))

        # make initial contact to set host/ip via discovery and pair the remote
        with open(DEVICE_FILE, 'rt') as fp: usn=fp.read()
        SERVER_IP, MODELNAME = getdeviceip(usn)
        ar = AndroidRemote(SERVER_IP)
        try:
            ar.connect() # try connect to see if pairing ok
            data = ar.ssl_sock.recv(1024) # dummy read, we need to receive to check if ok
        except ssl.SSLError as x:
            if x.args[1].find("sslv3 alert") == -1: raise
            ar.disconnect()
            ar.connect(pairing=True)
            if not ar.start_pairing(): sys.exit()
        finally:
            ar.disconnect()
            ar = None

# ----------------------------------------------
# create a queue for communication with remote-thread
# ----------------------------------------------
queue = queue.Queue()
stop_threads = False

# ----------------------------------------------
# Thread function for starting REMOTE
# ----------------------------------------------
def remote():

    with open(DEVICE_FILE, 'rt') as fp: usn=fp.read()
    SERVER_IP, MODELNAME = getdeviceip(usn)

    # main loop with PING/PONG and remote control
    try:
        ar = AndroidRemote(SERVER_IP)
        ar.connect()
        log.info("Starting REMOTE with device %s on %s" % (MODELNAME, SERVER_IP))
        ar.check_remote()
    except ssl.SSLError as x:
        if x.args[1].find("sslv3 alert") != -1:
            log.error("Certificate unknown, you need to re-pair. Remove client.pem and start on console.")
        else:
            log.info(x)
    except Exception as x:
        log.info(x)

    finally:
        ar.disconnect()
        ar = None

# ----------------------------------------------
# Thread function for UDP server
# ----------------------------------------------
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

class http_server:
    def __init__(self, t1):
        httpd = ThreadingHTTPServer(('0.0.0.0', 6468), myhandler)
        httpd.t1 = t1
        httpd.serve_forever()

class myhandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        data=self.path[1:].upper() # /Volume_up remove slash
        response = 'Ok... ' + data

        if not enumvalid('KEYCODE_'+data, remotemessage_pb2.RemoteKeyCode) is None or data=='STOP':
            if not self.server.t1.is_alive() and not data=='STOP':
                log.info('Remote was stopped and we now have a code (%s), so restarting REMOTE thread' % data)
                self.server.t1 = None
                self.server.t1 = threading.Thread(target=remote, args=())
                self.server.t1.start()
            if self.server.t1.is_alive(): queue.put(data)
        else:
            response = 'Wrong... ' + data

        if os.path.isfile(dir_path+'/'+data.lower()+'.html'):
            with open(dir_path+'/'+data.lower()+'.html', 'rt') as fp: response=fp.read()

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-length', len(response))
        self.end_headers()
        self.wfile.write(bytes(response, 'UTF-8'))

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    pass

def server():
    t1 = threading.Thread(target=remote, args=())
    # t1.start() # no need to start here. Just start when needed the first time
    srv = http_server(t1)

# ----------------------------------------------
#
# ----------------------------------------------
if __name__ == "__main__":

    check_device_and_choose()
    check_certificate_and_pair()

    with open(DEVICE_FILE, 'rt') as fp: usn=fp.read()
    log.info('We are using device "%s"' % usn)
    hostname = socket.getfqdn()
    log.info('');
    log.info('You can access a TV Remote page on http://%s/index or /index0' % socket.gethostbyname_ex(hostname)[2][1]);
    log.info('');
    #SERVER_IP, MODELNAME = getdeviceip(usn) # TV could be off at restart
    #log.info('We found device "%s" on %s' % (MODELNAME, SERVER_IP))

    try:
        server()
    except KeyboardInterrupt:
        log.error("Keyboard interrupt " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        sys.exit()
    except Exception as x:
        log.error("Error " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        log.error(x)
        sys.exit()
    finally:
        log.info("exit " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        stop_threads = True
        pass

