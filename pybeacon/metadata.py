import struct
import base64
import hashlib
import binascii
import StringIO
import sys

import M2Crypto
import requests

PRIVATE_KEY_TEMPLATE = "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----"
PUBLIC_KEY_TEMPLATE = "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----"

class Metadata(object):
    """
    Class to represent a beacon Metadata object
    """
    def __init__(self, data="", private_key="", public_key="", cs_version=4):
        self.cs_version = cs_version
        self.data = data
        self.public_key = public_key
        self.private_key = private_key
        self.port = 0
        self.ciphertext = ""
        self.charset = ""
        self.charset_oem = ""
        self.ver = ""
        self.intz = ""
        self.comp = ""
        self.user = ""
        self.pid = ""
        self.bid = ""
        self.barch = ""
        self.raw_aes_keys = ""
        self.aes_key = ""
        self.hmac_key = ""
        self.is64 = False
        self.high_integrity = False

        if data and len(data) != 128:
            raise AttributeError('Metadata should be 128 bytes')

        if data and private_key:
            self.rsa_decrypt()
            self.unpack()

    def calculate_aes(self):
        h = hashlib.sha256(self.raw_aes_keys)
        digest = h.digest()
        self.aes_key = digest[0:16]
        self.hmac_key = digest[16:]

    def rsa_decrypt(self):
        pkey = M2Crypto.RSA.load_key_string(PRIVATE_KEY_TEMPLATE.format(self.private_key))
        plaintext = pkey.private_decrypt(self.data, M2Crypto.RSA.pkcs1_padding)
        assert plaintext[0:4] == '\x00\x00\xBE\xEF'
        self.data = StringIO.StringIO(plaintext[8:])

    def rsa_encrypt(self):
        bio = M2Crypto.BIO.MemoryBuffer(PUBLIC_KEY_TEMPLATE.format(self.public_key))
        pubkey = M2Crypto.RSA.load_pub_key_bio(bio)
        data = '\x00\x00\xBE\xEF' + struct.pack('>I', self.data.len) + self.data.read()
        self.ciphertext = pubkey.public_encrypt(data, M2Crypto.RSA.pkcs1_padding)
        return base64.b64encode(self.ciphertext)

    def readInt(self, byteorder='>'):
        fmt = byteorder + 'L'
        return struct.unpack(fmt, self.data.read(struct.calcsize(fmt)))[0]

    def readShort(self, byteorder='>'):
        fmt = byteorder + 'H'
        return struct.unpack(fmt, self.data.read(struct.calcsize(fmt)))[0]

    def readByte(self):
        fmt = 'b'
        return struct.unpack(fmt, self.data.read(struct.calcsize(fmt)))[0]

    def writeInt(self, buf, byteorder='>'):
        fmt = byteorder + 'L'
        self.data.write(struct.pack(fmt, buf))

    def writeShort(self, buf, byteorder='>'):
        fmt = byteorder + 'H'
        self.data.write(struct.pack(fmt, buf))

    def writeByte(self, buf):
        fmt = 'b'
        self.data.write(struct.pack(fmt, buf))

    def flag(self, b, s):
        return b & s == s

    def unflag(self, b, s):
        return b & s == s

    def print_config(self):
        print "raw AES key: %s" % self.raw_aes_keys[0:8].encode('hex')
        print "raw HMAC key: %s" % self.raw_aes_keys[8:].encode('hex')
        print "AES key: %s" % self.aes_key.encode('hex')
        print "HMAC key: %s" % self.hmac_key.encode('hex')
        print "ver: %s" % self.ver
        print "host: %s" % self.intz
        print "computer: %s" % self.comp
        print "user: %s" % self.user        
        print "pid: %s" % self.pid
        print "id: %s" % self.bid
        print "barch: %s" % self.barch
        print "is64: %s" % self.is64

        if self.cs_version > 3:
            print "charset: %s" % self.charset
            print "port: %s" % self.port

    def unpack(self):
        self.data.seek(0)
        self.raw_aes_keys = self.data.read(16)
        self.calculate_aes()

        if self.cs_version < 4:           
            config = self.data.read().split('\t')
            self.bid = config[0]
            self.pid = config[1]
            self.ver = config[2]
            self.intz = config[3]
            self.comp = config[4]
            self.user = config[5]
            self.is64 = config[6]
            if config[7] == '1':
                self.barch = 'x64'
            else:
                self.barch = 'x86'
            return

        self.charset = self.readShort('<')
        self.charset_oem = self.readShort('<')
        self.bid = self.readInt()
        self.pid = self.readInt()
        self.port = self.readShort()        
        b = self.readByte()
       
        if self.flag(b, 1):
            self.barch = ""
            self.pid = ""
            self.is64 = ""
        elif self.flag(b, 2):
            self.barch = "x64"
        else:
            self.barch = "x86"

        self.is64 = int(self.flag(b, 4))
        self.high_integrity = self.flag(b, 8)
        self.ver, self.intz, self.comp, self.user, self.proc = self.data.read().split('\t')

    def pack(self):
        if not all([
            self.public_key,
            self.charset,
            self.charset_oem,
            self.ver,
            self.intz,
            self.comp,
            self.user,
            self.pid,
            self.bid,
            self.barch,
            self.raw_aes_keys,
            ]) and self.cs_version >= 4:
            raise AttributeError('Unable to pack data, due to missing properties')

        if not all([
            self.public_key,
            self.bid,
            self.pid,
            self.ver,
            self.intz,
            self.comp,
            self.user,
            self.is64,
            self.barch,
            self.raw_aes_keys
            ]) and self.cs_version < 4:
            raise AttributeError('Unable to pack data, due to missing properties')

        # CS 3.5
        if self.cs_version < 4:
            self.data = StringIO.StringIO()
            self.data.write(self.raw_aes_keys)
            self.data.write('\t'.join([
                str(self.bid),
                str(self.pid),
                self.ver,
                self.intz,
                self.comp,
                self.user,
                self.is64
                ]))
            if self.barch == 'x64':
                self.data.write("\t1")
            else:
                self.data.write("\t0")
            self.data.seek(0)
            return self.rsa_encrypt()

        # CS 4.0 and later
        self.data = StringIO.StringIO()
        self.data.write(self.raw_aes_keys)
        self.writeShort(self.charset, '<')
        self.writeShort(self.charset_oem, '<')
        self.writeInt(self.bid)
        self.writeInt(self.pid)
        self.writeShort(self.port)    
        self.writeByte(4) # TODO: calculate flags
        self.data.write('\t'.join([self.ver, self.intz, self.comp, self.user, self.proc]))
        self.data.seek(0)
        return self.rsa_encrypt()


if __name__ == "__main__":
    # Test data
    # CS 4.0
    m = Metadata(
        base64.b64decode('iMEqKb7V1aWwwr61GoFw+EFER8CFvejciH5XD3rwmlujIHkQiFvxFn5lC/spTT1JGOC++BQDEbXsH1tijkkAVswhoW9sN8z/pL5jCLkjIJ0dky9dWprwo/2dVkvrESEObrzSe8jzeaKCytAtm3/DoR6f+nRfgaoA4MCxbBi8uY8='),
        'MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAOE58LhMgJ6+tuCJRUrmSa9Txo1A2IJ9xwfEg5XjDOM6fkOloLj00ugoyxLZ9Wcwj9/5xvK6p+tcxiZRfx5kNaSZ+WsEU048byGvyiqGbUSIi8r1L4Kw64sawQ6Z5+piT4aPWd+cnW470QtG/VT46GZDvvDi7QBlYc9I2vVJNiFlAgMBAAECgYBfHZYAbyZ+Y/JdfvtJd1m09n9KlhEZgr60FBSyDxIZQFGkheULVzFepCOm0W9m5cZNA3I2fgd+SU7RTeeOUSmpkBp81Pq+TeFLMAgWVRtiGNPwR1CGiU4H18s8trQN9C6OY2f+d6ZMXVxPHI52SEwLq5fGjcg5ZguX74Qx34jJQQJBAPPYCd5vALwlh9f9G59fWnjZ8tJ34I1q5m641+b5kp5npjj8TAiItMqlM1O3C3ypL5kpvmSZjs0jlHoOU0Be9NUCQQDsdE1ntzClX2ko19Sg6IjywKSAkwshyT3dYxE/f6px4p4HEyV+VmCrAKTNLfixU70VkXyfnf5VXm13dF68vQJRAkAWW5OkEnd1yNcoxatXtI1+ETXDeHxdWxTfyBD7u5xm68gA55ktGyPAhN8s6NajyntzxrEPVkkSpBWED3Ywq8Q1AkEAt5cxxpa5AZ4MI3c5E9qZAorK7z28hfYfv7Y83SW97ID9HBckpGxi0ENGsjzAfMa86HM25SQiJpyTuA01xaunkQJACXKKA8lffC/fqaymbEpBaL51iefuBYJbYNPuiJzgwWyEdyuFjt5/dTQCJPscgfOnfCpujdeP65x0iGXwuIdkLA=='
        )
    m.print_config()
    m.public_key = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDhOfC4TICevrbgiUVK5kmvU8aNQNiCfccHxIOV4wzjOn5DpaC49NLoKMsS2fVnMI/f+cbyuqfrXMYmUX8eZDWkmflrBFNOPG8hr8oqhm1EiIvK9S+CsOuLGsEOmefqYk+Gj1nfnJ1uO9ELRv1U+OhmQ77w4u0AZWHPSNr1STYhZQIDAQAB'

    # CS 3.5
    m = Metadata(base64.b64decode('hwRRv0U1CkZSU5AOMHSNc6bvL73DpX2L6jrb5oWZeQwFD6TKJkJFF0Vri+0j8zTpxX9cjfbmcCQAGpqT23ZSB2A/p+3Oll5YnurDTSUDWKvCXzBdpUqgBg3GfsHj8dl549D1uYGhtDDrLFJ7Q/9OCCnjxJpm6heeaV4Bh+x07X8='),
        'MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJVY4v8Qezfp4pSArCfw0ACTqi3pCFGAuWYFmhTV/iENgcnpIBKWLblEo6CduZTyOdmzUIYT8To5uxFUnYKcrkTY7ucAspznyLxpcFFgL2CcHZlnVvblxdbU3uVvMp2vWMkhI5nU/tW9uD2JhNerbCHWrsRCC70T9C2AnE4gh9wXAgMBAAECgYBcrEJ3WefMA2LpGYs6YZEAuqCgSnkx8fmZmCJLiZpfMj12aCXRwsTusOwEL7tH9KL3NvDhsiA/LDGriGEQ+l6cQInKg2rBZSLgH9OTIWXVrsid15WonZxnw1hpQGJtJdmI9DH15Zux4zBiwOM5p9nF7pOdSs4XJZpQYkhthZlL0QJBANXPjrJrV3rOMS2zuqze3xKNoUjtPwv7hwj0p7NmCtETGwiWNpgv/egicw7lOcKgOeKXQPyvy2IpsRNyIb1Ye0kCQQCy0QP7h04wZmBIw1MaxgVodhLlhyVrm7UNvbTTAsu17ExUWW2J9mKnLseH/Oy1x2TWoK6sKsyTGygtIGecZTxfAkEAxnApt0xK165xFEKf+furu9N5Im8Wua9Lp7Mxxh3p4hvCVljb+KlqFT2L3gI/dnQw5S2OYjdiIwwgzbR6vfpWCQJAEiATqkRNzaQi8F00KEuYMr19LtzjEyRGVu06zgTDh147YnVqIAjkeRPJz+P4Tni2pPbGndb8w5CGIwTc28J7OwJBAKcvu9cKP+wvwk3fTFSctNhxErTzSCgBOzSKm3hNxau5ZpQ7R782pxw0/os5PNkBaJZvSqEZ0oER3Yiq7mCOocw=',
        cs_version=3)
    m.print_config()
