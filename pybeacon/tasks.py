
import hashlib
import hmac
import binascii
import base64
import sys
import struct
import random
import StringIO
import os
import time
import ntpath
 
from Crypto.Cipher import AES
 
HASH_ALGO = hashlib.sha256
SIG_SIZE = HASH_ALGO().digest_size

class AuthenticationError(Exception):
    pass

BEACON_OUTPUT = {
    1: 'OUTPUT_KEYSTROKES',
    2: 'DOWNLOAD_START',
    3: 'OUTPUT_SCREENSHOT',
    4: 'SOCKS_DIE',
    5: 'SOCKS_WRITE',
    6: 'SOCKS_RESUME',
    7: 'SOCKS_PORTFWD',
    8: 'DOWNLOAD_WRITE',
    9: 'DOWNLOAD_COMPLETE',
    10: 'BEACON_LINK',
    11: 'DEAD_PIPE',
    12: 'BEACON_CHECKIN', # maybe?
    13: 'BEACON_ERROR',
    14: 'PIPES_REGISTER', # unsure?
    15: 'BEACON_IMPERSONATED',
    16: 'BEACON_GETUID',
    17: 'BEACON_OUTPUT_PS',
    18: 'ERROR_CLOCK_SKEW',
    19: 'BEACON_GETCWD',
    20: 'BEACON_OUTPUT_JOBS',
    21: 'BEACON_OUTPUT_HASHES',
    22: 'TODO', # find out
    23: 'SOCKS_ACCEPT',
    24: 'BEACON_OUTPUT_NET',
    25: 'BEACON_OUTPUT_PORTSCAN',
    26: 'BEACON_EXIT',
    }

BEACON_COMMANDS = {
    4:  'SLEEP',
    11: 'DOWNLOAD_START',
    32: 'LIST_PROCESSES'
    }

CS_FIXED_IV = "abcdefghijklmnop"

class BeaconTask(object):
    """
    Class to represent an AES encrypted Beacon Task object
    """
    counter = 0

    def __init__(self, data="", aes_key="", hmac_key="", cs_version=4):
        self.cs_version = cs_version
        self.data = StringIO.StringIO(data)
        self.aes_key = aes_key
        self.hmac_key = hmac_key
        self.counter = self.tick()

    def tick(self):
        return int(time.time())

    def writeInt(self, buf, byteorder='>'):
        fmt = byteorder + 'L'
        self.data.write(struct.pack(fmt, buf))

    def readInt(self, byteorder='>'):
        fmt = byteorder + 'L'
        return struct.unpack(fmt, self.data.read(struct.calcsize(fmt)))[0]

    def readShort(self, byteorder='>'):
        fmt = byteorder + 'H'
        return struct.unpack(fmt, self.data.read(struct.calcsize(fmt)))[0]

    def compare_mac(self, mac, mac_verif):
        if len(mac) != len(mac_verif):
            print "invalid MAC size"
            return False 
        result = 0
        for x, y in zip(mac, mac_verif):
            result |= ord(x) ^ ord(y)
        return result == 0

    def decrypt(self):
        encrypted_data = self.data.read(self.data.len-16)
        signature = self.data.read()
        if not self.compare_mac(hmac.new(self.hmac_key, encrypted_data, HASH_ALGO).digest()[0:16], signature):
            raise AuthenticationError("message authentication failed")
        cypher = AES.new(self.aes_key, AES.MODE_CBC, CS_FIXED_IV)
        data = cypher.decrypt(encrypted_data)
        self.data = StringIO.StringIO(data)

        counter = self.readInt()
        print "Counter: %d" % counter

        output_length = self.readInt()
        print "Output length: %d" % output_length

        # adjust buffer length according to output_length
        self.data = StringIO.StringIO(self.data.read(output_length))

    def encrypt(self):
        # Prepend the counter and output_length
        self.data.seek(0)
        buf = self.data.read()
        self.data = StringIO.StringIO()
        self.writeInt(self.counter)
        self.writeInt(len(buf))
        self.data.write(buf)
        self.data.seek(0)
        data = self.data.read()

        # encrypt the data
        pad = AES.block_size - len(data) % AES.block_size
        data = data + pad * '\x00'
        cypher = AES.new(self.aes_key, AES.MODE_CBC, CS_FIXED_IV)
        encrypted_data = cypher.encrypt(data)
        sig = hmac.new(self.hmac_key, encrypted_data, HASH_ALGO).digest()[0:16]
        self.data = StringIO.StringIO(encrypted_data+sig)
        self.data.seek(0)

class BeaconReply(BeaconTask):
    callback_type = ''

    def get_callback(self):
        return BEACON_OUTPUT.get(self.callback_type, 'Unknown')

    def unpack(self):
        # Beacon Replies are prepended with encrypted length
        #self.data.seek(0)
        enc_size = self.readInt()
        print "Encrypted size: %d" % enc_size

        # remove any padding so HMAC checks out
        self.data = StringIO.StringIO(self.data.read(enc_size))
        self.decrypt()

        # what type of call back is it
        self.callback_type = self.readInt()
        print "Callback type: %s (%d)" % (self.get_callback(), self.callback_type)

    def pack(self):
        # this prepends the header to self.data
        self.data.seek(0)
        buf = self.data.read()
        self.data = StringIO.StringIO()
        self.writeInt(self.callback_type)
        self.data.write(buf)
        self.data.seek(0)
        self.encrypt()

class DownloadTask(BeaconReply):
    flen = 0
    callback_type = 2

    def __init__(self, data='', fid=0, filename='', aes_key='', hmac_key=''):
        if aes_key:
            self.aes_key = aes_key
        if hmac_key:
            self.hmac_key = hmac_key
        self.data = StringIO.StringIO(data)
        self.filename = filename
        self.fid = fid

    def print_task(self):
        print "Fid: %d" % self.fid
        print "Flen: %d" % self.flen
        print "Filename: %s" % self.filename

    def pack(self):
        # flen is the length of the file (not path)
        self.flen = len(ntpath.basename(self.filename))
        self.data = StringIO.StringIO()
        self.writeInt(self.fid)
        self.writeInt(self.flen)
        self.data.write(self.filename)
        self.data.seek(0)
        super(DownloadTask, self).pack()

    def unpack(self):
        #self.data.seek(0)
        self.fid = self.readInt()
        self.flen = self.readInt()
        self.filename = self.data.read()

class DownloadWrite(BeaconReply):
    flen = 0
    callback_type = 8
    filedata = ''

    def __init__(self, data='', fid=0, filedata='', aes_key='', hmac_key=''):
        if aes_key:
            self.aes_key = aes_key
        if hmac_key:
            self.hmac_key = hmac_key
        if filedata:
            self.filedata = filedata
        self.data = StringIO.StringIO(data)
        self.fid = int(fid)

    def print_task(self):
        print "Fid: %d" % self.fid
        print "Filedata: %s" % self.filedata

    def pack(self):
        self.writeInt(self.fid)
        self.data.write(self.filedata)
        self.data.seek(0)
        super(DownloadWrite, self).pack()

    def unpack(self):
        self.fid = self.readInt()
        self.filedata = self.data.read()


def counter():
    return int(time.time())

def process_beacon_task(task):
    task.decrypt()
    while (task.data.tell() != task.data.len):
        command = task.readInt()
        print "Received task: %s" % BEACON_COMMANDS.get(command, 'Unknown (%d)' % command)
        args_len = task.readInt()

        print "Arguments length: %d" % args_len
        args = task.data.read(args_len)
        
        if args_len == struct.calcsize('>I'):
            fmt = '<I'
            print "Arguments: %s" % struct.unpack(fmt, args[:struct.calcsize(fmt)])[0]
        else:
            print "Arguments: %s" % args

def process_beacon_callback(reply):
    # first we have to find out what callback type we are dealing with
    reply.unpack()

    if reply.get_callback() == 'DOWNLOAD_START':
        reply.__class__ = DownloadTask
    elif reply.get_callback() == 'DOWNLOAD_WRITE':
        reply.__class__ = DownloadWrite

    reply.unpack()
    reply.print_task()

def test_decrypt_callback():
    reply = BeaconReply(
        data=base64.b64decode('AAAAUOrK3JmtDZXhZ2Ngs6WK2QvYJThdh9m0iaAucCp2v6mEkaBx5SioFXja8WqjzXykbF5o4c+yRRTFnNhIKW9AS8oJSnCTiimKfe8LOX2OxTiCAAAAMCjP+eBx4om1PUvo8QE25nGk1JmwAY1G4hYWKbmr9LRLbJOVVAUdG6MkgkoHqGw96AAAADCxfftXVhy82kwzttv+zpuANvqKu16M6axUgjIs+Ka5j4ya+iBF1tgCpTCOqsWBPjI='),
        aes_key=binascii.unhexlify('441bbd3de3d52997298a8625def8f40c'), # AES key
        hmac_key=binascii.unhexlify('1ede48669d4346c0b0cf2ca15e498c10'),  # HMAC key
        cs_version=3)
    process_beacon_callback(reply)

def test_decrypt_tasking():
    task = BeaconReply(
        base64.b64decode('gdZeTETyUmxnemZQJGKSh7NL1Ub0APIZXqytGiwel1LosOf/Zx93TpcKoJVNHrXO'),
        aes_key=binascii.unhexlify('441bbd3de3d52997298a8625def8f40c'), # AES key
        hmac_key=binascii.unhexlify('1ede48669d4346c0b0cf2ca15e498c10'),  # HMAC key
        cs_version=3)
    process_beacon_task(task)

if __name__ == "__main__":
    # Run tests
    print "[*] Test decrypting a tasking from the server.."
    test_decrypt_tasking()

    print "\n[*] Test decrypting a download callback and modifying it.."
    test_decrypt_callback()
