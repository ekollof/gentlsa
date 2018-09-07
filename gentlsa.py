#!/usr/bin/env python3
"""
Tool for TLSA/DANE

Usage:
    gentlsa.py host <name> <port> [--info] [--cloudflare] [--dryrun]
    gentlsa.py cloudflare [--info] [--listzones]
    gentlsa.py file <certfile>
"""

import sys
import ssl
import hashlib
import M2Crypto

try:
    import CloudFlare
except ImportError:
    pass

from docopt import docopt
from pprint import pprint

debug = False


def checkcloudflare():
    if "CloudFlare" in sys.modules:
        return True
    return False


def getcerthttps(addr, port):
    conn = ssl.create_connection((addr, port))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
    sock = ctx.wrap_socket(conn, server_hostname=addr)  # SNI
    pem_cert = ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))
    response = M2Crypto.X509.load_cert_string(pem_cert)

    return response


def getcertfile(filename):
    return M2Crypto.X509.load_cert(filename)


def getcertpubhash(certobj):
    pubkey = certobj.get_pubkey().as_der()
    pubkeyhash = hashlib.sha256(pubkey).hexdigest()

    return pubkeyhash


def printcertinfo(certobj, showinfo):

        if showinfo:
            print(">>> Certificate Information:")
            print(f"Serial : {certobj.get_serial_number():x}")
            print(f"Issuer : {certobj.get_issuer().as_text()}")
            print(f"Subject: {certobj.get_subject().as_text()}")
            try:
                san = certobj.get_ext('subjectAltName')
                print("Subject Alternative Name(s): %s" % san.get_value())
            except LookupError:
                pass

            sig_start = certobj.get_not_before().get_datetime()
            sig_end = certobj.get_not_after().get_datetime()
            print(f"Certificate Inception:  {sig_start} {sig_start.tzname()}")
            print(f"Certificate Expiration: {sig_end} {sig_end.tzname()}")

        print(f"_443._tcp TLSA 3 1 1 {getcertpubhash(certobj)}")


def getcfzonelist(cf):
    ret = {}
    zonedata = cf.zones.get()
    return zonedata


def getcfzoneinfo(cf, zonename):
    ret = {}
    zonedata = cf.zones.get(params={'name': zonename})

    return zonedata


def main():
    args = docopt(__doc__)

    addr = args['<name>']
    port = args['<port>']

    cloudflare_loaded = checkcloudflare()

    if args["--cloudflare"] or args["cloudflare"]:
        if cloudflare_loaded:
            cf = CloudFlare.CloudFlare(debug=debug)
            zones = getcfzoneinfo(cf, addr)
            if not zones:
                print("Not managed by cloudflare. Bailing.")
                return -1
            if args["--info"]:
                print(">>> Cloudflare Information:")
                print(f"Zone name: {addr}")
                print(f"Zone ID: {zones[0]['id']}")
                print(f"Zone owner: {zones[0]['owner']['email']}")
                print(f"Name servers: {zones[0]['name_servers']}")
        else:
            print("Please install the cloudflare module for this to work.")
            return(-1)

    if args["host"]:
        certobj = getcerthttps(addr, port)
        printcertinfo(certobj, args['--info'])

    if args['file']:
        certobj = getcertfile(args['<certfile>'])
        printcertinfo(certobj)


if __name__ == '__main__':
    sys.exit(main())
