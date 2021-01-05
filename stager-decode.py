#!/usr/bin/env python

import sys
import struct
import string
import random
import requests
import argparse

DECODE_LOOP_START = 0x03f

USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.163 Safari/537.36"

def checksum8(s):
    return sum([ord(ch) for ch in s]) % 0x100

def gen_checksum8(x64=False):
    chk = string.ascii_letters + string.digits
    for _ in xrange(64):
        uri = "".join(random.sample(chk,3))
        r = "".join(sorted(list(string.ascii_letters+string.digits), key=lambda *args: random.random()))
        for char in r:
            if checksum8(uri + char) == 92 and x64 == False:
                return uri + char
            if checksum8(uri + char) == 93 and x64 == True:
                return uri + char

def download_beacon(host, x64=False):
    chk = gen_checksum8(x64)
    r = requests.get('http://%s/%s' % (host, chk), headers = {'User-Agent': USER_AGENT})
    if r.status_code == 200:
        return r.content
    print "Unable to retrieve stager"
    sys.exit(1)

def xor(key, buf):
    return ''.join([(chr(ord(x) ^ ord(key[n % len(key)]))) for n, x in enumerate(buf)])

def read4(buf):
    return buf[4:], buf[0:4]

def find_start_index(buf):
    i = 0
    while i < len(buf):
        key = buf[i:i+4]
        _bytes = buf[i+8:i+12]
        outbuf = xor(key, _bytes)
        if outbuf[0:2] == '\x4d\x5a':
            break
        i+= 1
    return i

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Beacon stager decoder")
    parser.add_argument("-f", "--file", help="Beacon blob to decode", required=False)
    parser.add_argument("-d", "--download", help="Host to download beacon from", required=False)
    parser.add_argument('-o', "--output", help="Output file for decoded DLL", required=True)
    parser.add_argument('-x64', help="Whether to dump x64 beacon (x86 by default)", action='store_true', default=False)
    args = parser.parse_args()

    if args.file:
        with open(args.file, 'rb') as f:
            buf = f.read()
    elif args.download:
        buf = download_beacon(args.download, args.x64)
    else:
        args.print_usage()
        sys.exit(1)

    DECODE_LOOP_START = find_start_index(buf)

    buf = buf[DECODE_LOOP_START:]
    print "[*] Index: %d" % DECODE_LOOP_START

    buf, key = read4(buf)
    print "[*] Initial Key: 0x%s" % key.encode('hex')

    buf, size_enc = read4(buf)
    print "[*] DLL Size: %d" % struct.unpack("<I", xor(key, size_enc))[0]

    outbuf = ""
    while len(buf) > 0:
        buf, _bytes = read4(buf)
        outbuf += xor(key, _bytes)
        key = xor(key, outbuf[-4:])

    with open(args.output, 'wb') as f:
        f.write(outbuf)

    print "[+] Beacon decoded and written to: %s" % args.output
