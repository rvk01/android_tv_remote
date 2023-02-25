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
__version__ = "0.0.1"

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
CERT_FILE=dir_path + "/client.pem" # ook het Path gebruikt, zodat duidelijk is waar dit bestand staat

SERVER_IP = '1.1.1.1'


# ----------------------------------------------
#
# ----------------------------------------------
log = logging.getLogger("tv_remote")
logging.basicConfig()
log.setLevel(logging.INFO)

# ----------------------------------------------
# All Keycodes
# ----------------------------------------------
KEYCODE_UNKNOWN = 0;
KEYCODE_SOFT_LEFT = 1;
KEYCODE_SOFT_RIGHT = 2;
KEYCODE_HOME = 3;
KEYCODE_BACK = 4;
KEYCODE_CALL = 5;
KEYCODE_ENDCALL = 6;
KEYCODE_0 = 7;
KEYCODE_1 = 8;
KEYCODE_2 = 9;
KEYCODE_3 = 10;
KEYCODE_4 = 11;
KEYCODE_5 = 12;
KEYCODE_6 = 13;
KEYCODE_7 = 14;
KEYCODE_8 = 15;
KEYCODE_9 = 16;
KEYCODE_STAR = 17;
KEYCODE_POUND = 18;
KEYCODE_DPAD_UP = 19;
KEYCODE_DPAD_DOWN = 20;
KEYCODE_DPAD_LEFT = 21;
KEYCODE_DPAD_RIGHT = 22;
KEYCODE_DPAD_CENTER = 23;
KEYCODE_VOLUME_UP = 24;
KEYCODE_VOLUME_DOWN = 25;
KEYCODE_POWER = 26;
KEYCODE_CAMERA = 27;
KEYCODE_CLEAR = 28;
KEYCODE_A = 29;
KEYCODE_B = 30;
KEYCODE_C = 31;
KEYCODE_D = 32;
KEYCODE_E = 33;
KEYCODE_F = 34;
KEYCODE_G = 35;
KEYCODE_H = 36;
KEYCODE_I = 37;
KEYCODE_J = 38;
KEYCODE_K = 39;
KEYCODE_L = 40;
KEYCODE_M = 41;
KEYCODE_N = 42;
KEYCODE_O = 43;
KEYCODE_P = 44;
KEYCODE_Q = 45;
KEYCODE_R = 46;
KEYCODE_S = 47;
KEYCODE_T = 48;
KEYCODE_U = 49;
KEYCODE_V = 50;
KEYCODE_W = 51;
KEYCODE_X = 52;
KEYCODE_Y = 53;
KEYCODE_Z = 54;
KEYCODE_COMMA = 55;
KEYCODE_PERIOD = 56;
KEYCODE_ALT_LEFT = 57;
KEYCODE_ALT_RIGHT = 58;
KEYCODE_SHIFT_LEFT = 59;
KEYCODE_SHIFT_RIGHT = 60;
KEYCODE_TAB = 61;
KEYCODE_SPACE = 62;
KEYCODE_SYM = 63;
KEYCODE_EXPLORER = 64;
KEYCODE_ENVELOPE = 65;
KEYCODE_ENTER = 66;
KEYCODE_DEL = 67;
KEYCODE_GRAVE = 68;
KEYCODE_MINUS = 69;
KEYCODE_EQUALS = 70;
KEYCODE_LEFT_BRACKET = 71;
KEYCODE_RIGHT_BRACKET = 72;
KEYCODE_BACKSLASH = 73;
KEYCODE_SEMICOLON = 74;
KEYCODE_APOSTROPHE = 75;
KEYCODE_SLASH = 76;
KEYCODE_AT = 77;
KEYCODE_NUM = 78;
KEYCODE_HEADSETHOOK = 79;
KEYCODE_FOCUS = 80;
KEYCODE_PLUS = 81;
KEYCODE_MENU = 82;
KEYCODE_NOTIFICATION = 83;
KEYCODE_SEARCH = 84;
KEYCODE_MEDIA_PLAY_PAUSE= 85;
KEYCODE_MEDIA_STOP = 86;
KEYCODE_MEDIA_NEXT = 87;
KEYCODE_MEDIA_PREVIOUS = 88;
KEYCODE_MEDIA_REWIND = 89;
KEYCODE_MEDIA_FAST_FORWARD = 90;
KEYCODE_MUTE = 91;
KEYCODE_PAGE_UP = 92;
KEYCODE_PAGE_DOWN = 93;
KEYCODE_PICTSYMBOLS = 94;
KEYCODE_SWITCH_CHARSET = 95;
KEYCODE_BUTTON_A = 96;
KEYCODE_BUTTON_B = 97;
KEYCODE_BUTTON_C = 98;
KEYCODE_BUTTON_X = 99;
KEYCODE_BUTTON_Y = 100;
KEYCODE_BUTTON_Z = 101;
KEYCODE_BUTTON_L1 = 102;
KEYCODE_BUTTON_R1 = 103;
KEYCODE_BUTTON_L2 = 104;
KEYCODE_BUTTON_R2 = 105;
KEYCODE_BUTTON_THUMBL = 106;
KEYCODE_BUTTON_THUMBR = 107;
KEYCODE_BUTTON_START = 108;
KEYCODE_BUTTON_SELECT = 109;
KEYCODE_BUTTON_MODE = 110;
KEYCODE_ESCAPE = 111;
KEYCODE_FORWARD_DEL = 112;
KEYCODE_CTRL_LEFT = 113;
KEYCODE_CTRL_RIGHT = 114;
KEYCODE_CAPS_LOCK = 115;
KEYCODE_SCROLL_LOCK = 116;
KEYCODE_META_LEFT = 117;
KEYCODE_META_RIGHT = 118;
KEYCODE_FUNCTION = 119;
KEYCODE_SYSRQ = 120;
KEYCODE_BREAK = 121;
KEYCODE_MOVE_HOME = 122;
KEYCODE_MOVE_END = 123;
KEYCODE_INSERT = 124;
KEYCODE_FORWARD = 125;
KEYCODE_MEDIA_PLAY = 126;
KEYCODE_MEDIA_PAUSE = 127;
KEYCODE_MEDIA_CLOSE = 128;
KEYCODE_MEDIA_EJECT = 129;
KEYCODE_MEDIA_RECORD = 130;
KEYCODE_F1 = 131;
KEYCODE_F2 = 132;
KEYCODE_F3 = 133;
KEYCODE_F4 = 134;
KEYCODE_F5 = 135;
KEYCODE_F6 = 136;
KEYCODE_F7 = 137;
KEYCODE_F8 = 138;
KEYCODE_F9 = 139;
KEYCODE_F10 = 140;
KEYCODE_F11 = 141;
KEYCODE_F12 = 142;
KEYCODE_NUM_LOCK = 143;
KEYCODE_NUMPAD_0 = 144;
KEYCODE_NUMPAD_1 = 145;
KEYCODE_NUMPAD_2 = 146;
KEYCODE_NUMPAD_3 = 147;
KEYCODE_NUMPAD_4 = 148;
KEYCODE_NUMPAD_5 = 149;
KEYCODE_NUMPAD_6 = 150;
KEYCODE_NUMPAD_7 = 151;
KEYCODE_NUMPAD_8 = 152;
KEYCODE_NUMPAD_9 = 153;
KEYCODE_NUMPAD_DIVIDE = 154;
KEYCODE_NUMPAD_MULTIPLY = 155;
KEYCODE_NUMPAD_SUBTRACT = 156;
KEYCODE_NUMPAD_ADD = 157;
KEYCODE_NUMPAD_DOT = 158;
KEYCODE_NUMPAD_COMMA = 159;
KEYCODE_NUMPAD_ENTER = 160;
KEYCODE_NUMPAD_EQUALS = 161;
KEYCODE_NUMPAD_LEFT_PAREN = 162;
KEYCODE_NUMPAD_RIGHT_PAREN = 163;
KEYCODE_VOLUME_MUTE = 164;
KEYCODE_INFO = 165;
KEYCODE_CHANNEL_UP = 166;
KEYCODE_CHANNEL_DOWN = 167;
KEYCODE_ZOOM_IN = 168;
KEYCODE_ZOOM_OUT = 169;
KEYCODE_TV = 170;
KEYCODE_WINDOW = 171;
KEYCODE_GUIDE = 172;
KEYCODE_DVR = 173;
KEYCODE_BOOKMARK = 174;
KEYCODE_CAPTIONS = 175;
KEYCODE_SETTINGS = 176;
KEYCODE_TV_POWER = 177;
KEYCODE_TV_INPUT = 178;
KEYCODE_STB_POWER = 179;
KEYCODE_STB_INPUT = 180;
KEYCODE_AVR_POWER = 181;
KEYCODE_AVR_INPUT = 182;
KEYCODE_PROG_RED = 183;
KEYCODE_PROG_GREEN = 184;
KEYCODE_PROG_YELLOW = 185;
KEYCODE_PROG_BLUE = 186;
KEYCODE_APP_SWITCH = 187;
KEYCODE_BUTTON_1 = 188;
KEYCODE_BUTTON_2 = 189;
KEYCODE_BUTTON_3 = 190;
KEYCODE_BUTTON_4 = 191;
KEYCODE_BUTTON_5 = 192;
KEYCODE_BUTTON_6 = 193;
KEYCODE_BUTTON_7 = 194;
KEYCODE_BUTTON_8 = 195;
KEYCODE_BUTTON_9 = 196;
KEYCODE_BUTTON_10 = 197;
KEYCODE_BUTTON_11 = 198;
KEYCODE_BUTTON_12 = 199;
KEYCODE_BUTTON_13 = 200;
KEYCODE_BUTTON_14 = 201;
KEYCODE_BUTTON_15 = 202;
KEYCODE_BUTTON_16 = 203;
KEYCODE_LANGUAGE_SWITCH = 204;
KEYCODE_MANNER_MODE = 205;
KEYCODE_3D_MODE = 206;
KEYCODE_CONTACTS = 207;
KEYCODE_CALENDAR = 208;
KEYCODE_MUSIC = 209;
KEYCODE_CALCULATOR = 210;
KEYCODE_ZENKAKU_HANKAKU = 211;
KEYCODE_EISU = 212;
KEYCODE_MUHENKAN = 213;
KEYCODE_HENKAN = 214;
KEYCODE_KATAKANA_HIRAGANA = 215;
KEYCODE_YEN = 216;
KEYCODE_RO = 217;
KEYCODE_KANA = 218;
KEYCODE_ASSIST = 219;
KEYCODE_BRIGHTNESS_DOWN = 220;
KEYCODE_BRIGHTNESS_UP = 221;
KEYCODE_MEDIA_AUDIO_TRACK = 222;
KEYCODE_SLEEP = 223;
KEYCODE_WAKEUP = 224;
KEYCODE_PAIRING = 225;
KEYCODE_MEDIA_TOP_MENU = 226;
KEYCODE_11 = 227;
KEYCODE_12 = 228;
KEYCODE_LAST_CHANNEL = 229;
KEYCODE_TV_DATA_SERVICE = 230;
KEYCODE_VOICE_ASSIST = 231;
KEYCODE_TV_RADIO_SERVICE = 232;
KEYCODE_TV_TELETEXT = 233;
KEYCODE_TV_NUMBER_ENTRY = 234;
KEYCODE_TV_TERRESTRIAL_ANALOG = 235;
KEYCODE_TV_TERRESTRIAL_DIGITAL = 236;
KEYCODE_TV_SATELLITE = 237;
KEYCODE_TV_SATELLITE_BS = 238;
KEYCODE_TV_SATELLITE_CS = 239;
KEYCODE_TV_SATELLITE_SERVICE = 240;
KEYCODE_TV_NETWORK = 241;
KEYCODE_TV_ANTENNA_CABLE = 242;
KEYCODE_TV_INPUT_HDMI_1 = 243;
KEYCODE_TV_INPUT_HDMI_2 = 244;
KEYCODE_TV_INPUT_HDMI_3 = 245;
KEYCODE_TV_INPUT_HDMI_4 = 246;
KEYCODE_TV_INPUT_COMPOSITE_1 = 247;
KEYCODE_TV_INPUT_COMPOSITE_2 = 248;
KEYCODE_TV_INPUT_COMPONENT_1 = 249;
KEYCODE_TV_INPUT_COMPONENT_2 = 250;
KEYCODE_TV_INPUT_VGA_1 = 251;
KEYCODE_TV_AUDIO_DESCRIPTION = 252;
KEYCODE_TV_AUDIO_DESCRIPTION_MIX_UP = 253;
KEYCODE_TV_AUDIO_DESCRIPTION_MIX_DOWN = 254;
KEYCODE_TV_ZOOM_MODE = 255;
KEYCODE_TV_CONTENTS_MENU = 256;
KEYCODE_TV_MEDIA_CONTEXT_MENU = 257;
KEYCODE_TV_TIMER_PROGRAMMING = 258;
KEYCODE_HELP = 259;
KEYCODE_NAVIGATE_PREVIOUS = 260;
KEYCODE_NAVIGATE_NEXT = 261;
KEYCODE_NAVIGATE_IN = 262;
KEYCODE_NAVIGATE_OUT = 263;
KEYCODE_STEM_PRIMARY = 264;
KEYCODE_STEM_1 = 265;
KEYCODE_STEM_2 = 266;
KEYCODE_STEM_3 = 267;
KEYCODE_DPAD_UP_LEFT = 268;
KEYCODE_DPAD_DOWN_LEFT = 269;
KEYCODE_DPAD_UP_RIGHT = 270;
KEYCODE_DPAD_DOWN_RIGHT = 271;
KEYCODE_MEDIA_SKIP_FORWARD = 272;
KEYCODE_MEDIA_SKIP_BACKWARD = 273;
KEYCODE_MEDIA_STEP_FORWARD = 274;
KEYCODE_MEDIA_STEP_BACKWARD = 275;
KEYCODE_SOFT_SLEEP = 276;
KEYCODE_CUT = 277;
KEYCODE_COPY = 278;
KEYCODE_PASTE = 279;
KEYCODE_SYSTEM_NAVIGATION_UP = 280;
KEYCODE_SYSTEM_NAVIGATION_DOWN = 281;
KEYCODE_SYSTEM_NAVIGATION_LEFT = 282;
KEYCODE_SYSTEM_NAVIGATION_RIGHT = 283;
KEYCODE_ALL_APPS = 284;
KEYCODE_REFRESH = 285;
KEYCODE_THUMBS_UP = 286;
KEYCODE_THUMBS_DOWN = 287;
KEYCODE_PROFILE_SWITCH = 288;
KEYCODE_VIDEO_APP_1 = 289;
KEYCODE_VIDEO_APP_2 = 290;
KEYCODE_VIDEO_APP_3 = 291;
KEYCODE_VIDEO_APP_4 = 292;
KEYCODE_VIDEO_APP_5 = 293;
KEYCODE_VIDEO_APP_6 = 294;
KEYCODE_VIDEO_APP_7 = 295;
KEYCODE_VIDEO_APP_8 = 296;
KEYCODE_FEATURED_APP_1 = 297;
KEYCODE_FEATURED_APP_2 = 298;
KEYCODE_FEATURED_APP_3 = 299;
KEYCODE_FEATURED_APP_4 = 300;
KEYCODE_DEMO_APP_1 = 301;
KEYCODE_DEMO_APP_2 = 302;
KEYCODE_DEMO_APP_3 = 303;
KEYCODE_DEMO_APP_4 = 304;

def discover(timeout=1.0, retries=1):
    locations = []
    group = ('239.255.255.250', 1900)
    service = 'urn:dial-multiscreen-org:service:dial:1'
    message = '\r\n'.join(['M-SEARCH * HTTP/1.1', 'HOST: {group[0]}:{group[1]}',
        'MAN: "ssdp:discover"', 'ST: {st}', 'MX: 3', '', '']).format(group=group, st=service)
    #print(message)
    socket.setdefaulttimeout(timeout)
    for _ in range(retries):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.sendto(message.encode('utf-8'), group)
        while True:
            try:
                response = sock.recv(2048).decode('utf-8')
                for line in response.split('\r\n'):
                    if line.startswith('LOCATION: '):
                        location = line.split(' ')[1].strip()
                        if not location in locations:
                            locations.append(location)
            except socket.timeout:
                break
    return locations


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
        log.info('connecting to ' + self.host + ' 6467 pairing port' if pairing else ' 6466 remote port')

    def disconnect(self):
        self.ssl_sock.shutdown(socket.SHUT_RDWR)
        self.ssl_sock.close()
        log.info('disconnected')

    def send_message(self, msg):
        log.debug('---> ' + str(msg))
        self.ssl_sock.send((len(msg)).to_bytes(1, byteorder='big'))
        self.ssl_sock.send(msg)

    def start_pairing(self):

        buffer=bytearray()

        payload=[ 8, 2, 16, 200, 1, 82, 43, 10,
              21, 105, 110, 102, 111, 46, 107, 111, 100, 111, 110, 111, 46, 97, 115, 115, 105, 115, 116, 97, 110, 116,
              18, 13, 105, 110, 116, 101, 114, 102, 97, 99, 101, 32, 119, 101, 98]
        message = bytearray(payload)
        self.send_message(message)

        while True:

            data = self.ssl_sock.recv(1024)
            buffer = buffer + data

            if (len(buffer) > 1) and (buffer[0] <= len(buffer) - 1):

                log.debug('recv ' + str(buffer))

                if (buffer[0] == 7) and (buffer[6] == 90):
                    # pair response [ 8, 2, 16, 200, 1, 90, 0 ]
                    log.info('receive pairing response')
                    log.info('send options')
                    payload = [ 8, 2, 16, 200, 1, 162, 1, 8, 10, 4, 8, 3, 16, 6, 24, 1 ]
                    message = bytearray(payload)
                    self.send_message(message)

                if (buffer[0] == 16) and (buffer[6] == 162):
                    # option response [ 8, 2, 16, 200, 1, 162, 1, 8, 18, 4, 8, 3, 16, 6, 24, 1 ]
                    log.info('receive option response')
                    log.info('Send config');
                    payload = [ 8, 2, 16, 200, 1, 242, 1, 8, 10, 4, 8, 3, 16, 6, 16, 1 ];
                    message = bytearray(payload)
                    self.send_message(message)

                if (buffer[0] == 8) and (buffer[6] == 250):
                    # config response [ 8, 2, 16, 200, 1, 250, 1, 0 ]
                    log.info('receive config response')

                    input_code = input('Enter LAST 4 DIGITS from TV code? ')

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
                    p = [ 8, 2, 16, 200, 1, 194, 2, 34, 10, 32] # + 32 bytes secret 42 bytes !
                    message[0:0] = p
                    self.send_message(message)

                if (buffer[0] == 5) and (buffer[4] in [144, 146]):
                    # response [ 6, 5, 8, 2, 16, 144, 3]
                    log.info('receive wrong TV secret code')
                    log.info('pairing unsuccesful')
                    return False

                if (buffer[0] == 42) and (buffer[4] == 200):
                    # secret [ 42 8 2 16 200 1 202 2 34 10 32 221 201 193 143 1 1 138 93 202 61 97 186 180 109 33 56 144 252 20 57 13 28 49 249 7 88 250 223 218 2 91 128 ]
                    log.info('receive correct TV secret code')
                    log.info('pairing success');
                    return True

                log.debug('rmov ' + str(buffer))
                del buffer[0:buffer[0] + 1] # remove message from buffer
                log.debug('rest ' + str(buffer))


    def start_remote(self):

        buffer=bytearray()

        while True:

            data = self.ssl_sock.recv(1024)
            buffer = buffer + data

            if (len(buffer) > 1) and (buffer[0] <= len(buffer) - 1):

                log.debug('recv ' + str(buffer))

                if (buffer[0] > 10) and (buffer[1] == 10):
                    # 1e message  [ 106 10, 73, 8, 238, 4, 18, 60, 10, 15, 65,
                    log.info('receive 1st message')
                    log.info('sending 1st message');
                    payload = [ 10, 66, 8, 238, 4, 18, 61, 10, 15, 65,
                    115, 115, 105, 115, 116, 97, 110, 116, 32, 67, 108, 111, 117, 100, 18, 6, 75, 111, 100, 111, 110, 111, 24, 1, 34, 2, 49, 48, 42, 21, 105, 110, 102, 111, 46,
                    107, 111, 100, 111, 110, 111, 46, 97, 115, 115, 105, 115, 116, 97, 110, 116, 50, 5, 49, 46, 48, 46, 48]
                    message = bytearray(payload)
                    self.send_message(message)

                if (buffer[0] > 1) and (buffer[1] == 18):
                    # 2e message // [ 2, 18, 0 ]
                    log.info('receive 2nd message')
                    log.info('sending 2nd message');
                    payload = [ 18, 3, 8, 238, 4]
                    message = bytearray(payload)
                    self.send_message(message)

                if (buffer[0] > 2) and (buffer[1] == 194):
                    log.info('WE HAVE A CONNECTION')
                    return True

                if (buffer[0] > 2) and (buffer[1] == 66):
                    # PING // [10, 66, 8, 8, 1, 16, 193, 249, 197, 163, 9]
                    log.info('PING')
                    log.info('PONG');
                    payload = [ 74, 2, 8, 25]
                    message = bytearray(payload)
                    self.send_message(message)

                log.debug('rmov ' + str(buffer))
                del buffer[0:buffer[0] + 1] # remove message from buffer

    def check_remote(self):

        buffer=bytearray()

        while True:

            # we receive commands via queue, execute them
            if not queue.empty():
              data = queue.get()
              if data=='STOP':
                  # test exception to see if thread can restart itself
                  raise Exception("Test exception")
              self.dostring('KEYCODE_' + data)


            socket_list = [self.ssl_sock]
            read_sockets, write_sockets, error_sockets = select.select(socket_list , [], [], 0)
            data = None
            for sock in read_sockets:
                if sock == self.ssl_sock:
                    data = self.ssl_sock.recv(1024)
            if data == None: continue

            buffer = buffer + data
            log.debug('recv ' + str(buffer))

            if (len(buffer) > 1) and (buffer[0] <= len(buffer) - 1):

                log.debug('recv ' + str(buffer))

                if (buffer[0] > 2) and (buffer[1] == 66):
                    # PING // [10, 66, 8, 8, 1, 16, 193, 249, 197, 163, 9]
                    log.info('PING')
                    log.info('PONG');
                    payload = [ 74, 2, 8, 25]
                    message = bytearray(payload)
                    self.send_message(message)

                log.debug('rmov ' + str(buffer))
                del buffer[0:buffer[0] + 1] # remove message from buffer

    def sendkey(self, KEY):
        payload = [ 82, 4, 8, KEY, 16, 1 ]
        message = bytearray(payload)
        self.send_message(message)
        payload = [ 82, 4, 8, KEY, 16, 2 ]
        message = bytearray(payload)
        self.send_message(message)

    def sendcommand(self, KEY):
        payload = [ 82, 5, 8, KEY, 1, 16, 3 ]
        message = bytearray(payload)
        self.send_message(message)

    def dostring(self, cmd):
        if not cmd in globals(): return
        i=globals()[cmd]
        log.info('Send %s' % cmd)

        if not i in [KEYCODE_CHANNEL_UP, KEYCODE_CHANNEL_DOWN]:
            # keycodes
            self.sendkey(i)
        else:
            # commands
            self.sendcommand(i)

# ----------------------------------------------
# create a queue for communication with remote-thread
# ----------------------------------------------
queue = queue.Queue()

# ----------------------------------------------
# Thread function for starting REMOTE
# ----------------------------------------------
def remote():
    ar = AndroidRemote(SERVER_IP)
    try:
        ar.connect()
        if not ar.start_remote(): sys.exit()
    except Exception as x:
        log.info(x)
        # if str(x).find("SSLV3_ALERT_CERTIFICATE_UNKNOWN") == -1: raise
        ar.disconnect()
        ar.connect(pairing=True)
        if not ar.start_pairing(): sys.exit()
    log.info("Starting REMOTE")

    # main loop with PING/PONG and remote control
    try:
        ar.check_remote()
    except Exception as x:
        log.info(x)
    finally:
        ar.disconnect()

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
    def do_GET(self):
        data=self.path[1:].upper() # /Volume_up remove slash
        response = 'Ok... ' + data

        if 'KEYCODE_'+data in globals() or data=='STOP':

            if not self.server.t1.is_alive() and not data=='STOP':
                log.info('Remote was stopped and we now have a code (%s), so restarting REMOTE thread' % data)
                self.server.t1 = None
                self.server.t1 = threading.Thread(target=remote, args=())
                self.server.t1.start()

            if self.server.t1.is_alive(): queue.put(data)

        else:

            response = 'Wrong... ' + data


        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.send_header('Content-length', len(response))
        self.end_headers()
        self.wfile.write(bytes(response, 'UTF-8'))

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    pass

def server():
    t1 = threading.Thread(target=remote, args=())
    # t1.start() # no need to start here. Just start when needed the first time
    srv = http_server(t1)

def getdeviceip():
    devices = discover()
    for device in devices:
        r = requests.get(device)

        # dom = etree.fromstring(r.text)
        # Remove namespace prefixes
        # for elem in dom.getiterator(): elem.tag = elem.xpath('local-name()')
        # x = dom.xpath('/root/device/modelName/text()')

        o = urllib.parse.urlsplit(device)
        d = SimpleXMLElement(r.text)
        x = str(next(d.modelName()))

        return(o.hostname, x)  # print(x[0])

# ----------------------------------------------
#
# ----------------------------------------------
if __name__ == "__main__":

    SERVER_IP, MODELNAME = getdeviceip()
    log.info('We found device "%s" on %s' % (MODELNAME, SERVER_IP))
    # x = input("Enter two values: ").split()

    # We always need a certificate, create one if it does not exists
    if not os.path.isfile(CERT_FILE):
        log.info("Generating certificate")
        cert, key = generate_selfsigned_cert("atvremote")
        with open(CERT_FILE, "wt") as f: f.write(cert.decode("utf-8") + key.decode("utf-8"))

        # make initial contact to set host/ip via discovery and pair the remote

    try:

        server()

    except KeyboardInterrupt:
        log.error("Keyboard interrupt " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    except Exception as x:
        log.error("Error " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        log.error(x)
    finally:
        log.info("exit " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        pass

