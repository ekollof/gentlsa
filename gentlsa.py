#!/usr/bin/env python3
"""
Tool for TLSA/DANE

Usage:
    gentlsa.py generate <zone> <port> [--hostname <shorthost>] [--info] [--cloudflare] [--dryrun]
    gentlsa.py verify <zone> <port> [--hostname <shorthost>] [--info]
    gentlsa.py cloudflare [--info] [--listzones] # not implemented yet
    gentlsa.py file <certfile>
"""

import sys
import ssl
import dns.resolver
import smtplib
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


def getsmtpcert(addr, port):
    serv = smtplib.SMTP(addr, port=port)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
    serv.starttls(context=ctx)
    der = serv.sock.getpeercert(True)
    pem = ssl.DER_cert_to_PEM_cert(der)
    response = M2Crypto.X509.load_cert_string(pem)
    return response


def getcertfile(filename):
    return M2Crypto.X509.load_cert(filename)


def getcertpubhash(certobj):
    """
    Method 1: Hash from public key
    :param certobj:
    :return:
    """
    pubkey = certobj.get_pubkey().as_der()
    pubkeyhash = hashlib.sha256(pubkey).hexdigest()

    return pubkeyhash


def getcerthash(certobj):
    """
    Method 0: Hash from cert
    :param certobj:
    :return:
    """
    cert = certobj.as_der()
    certhash = hashlib.sha256(cert).hexdigest()

    return certhash


def printcertinfo(certobj, hostname, portnumber, showinfo):
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

    if hostname:
        print(f"_{portnumber}._tcp.{hostname} TLSA 3 1 1 {getcertpubhash(certobj)}")
    else:
        print(f"_{portnumber}._tcp TLSA 3 1 1 {getcertpubhash(certobj)}")


def getcfzonelist(cf):
    zonedata = cf.zones.get()
    return zonedata


def getcfzoneinfo(cf, zonename):
    zonedata = cf.zones.get(params={'name': zonename})
    return zonedata


def createcftlsa(cf, zonename, zoneid, host, port, tlsarec):
    tlsa = {
        "name": f"_{port}._tcp",
        "type": "TLSA",
        "data": {
            "method": 1,
            "usage": 3,
            "selector": 1,
            "matching_type": 1,
            "certificate": tlsarec,
        },
    }

    if host:
        tlsa['name'] = f"_{port}._tcp.{host}"

    # check if TLSA already exists
    r = cf.zones.dns_records.get(zoneid, params={'type': 'TLSA'})

    if debug:
        pprint(r)

    # TODO: This should probably be refactored.
    if not r:  # TLSA doesn't exist al all
        try:
            r = cf.zones.dns_records.post(zoneid, data=tlsa)
        except CloudFlare.exceptions.CloudFlareAPIError as msg:
            exit(f"Something went screwy: {zonename} - Error: {msg}")
        else:
            print(f"Cloudflare: TLSA record added for {zonename}")
            return

    for rr in r:
        rrid = rr['id']
        if rr['name'] == f'_{port}._tcp.{zonename}' or rr['name'] == f'_{port}._tcp.{host}.{zonename}':
            if debug:
                print("GOTCHA!")
            try:
                r = cf.zones.dns_records.put(zoneid, rrid, data=tlsa)
            except CloudFlare.exceptions.CloudFlareAPIError as msg:
                exit(f"Something went screwy: {zonename} - Error: {msg}")
            else:
                print(f"Cloudflare: TLSA record updated for {zonename}")
                return

    # if we get here, there is another TLSA record present, but not for our intended service. So we just create one.
    try:
        r = cf.zones.dns_records.post(zoneid, data=tlsa)
    except CloudFlare.exceptions.CloudFlareAPIError as msg:
        exit(f"Something went screwy: {zonename} - Error: {msg}")
    else:
        print(f"Cloudflare: TLSA record added for {zonename}")
        return

    print("How did we get here?")
    return False  # we shouldn't even get here.


def gettlsa(zonename, hostname, port):

    rr = ""
    if hostname:
        rr = f"_{port}._tcp.{hostname}"
    else:
        rr = f"_{port}._tcp"

    try:
        answers = dns.resolver.query(f"{rr}.{zonename}", "TLSA")
        return answers[0]
    except Exception as ex:
        print(f"Exception occured: {ex}")
        return None





def main():
    args = docopt(__doc__)

    zonename = args['<zone>']
    hostname = args['<shorthost>']
    port = args['<port>']

    certobj = None

    if debug:
        pprint(args)

    connhost = zonename
    if args['--hostname']:
        connhost = f"{args['<shorthost>']}.{zonename}"

    if args["generate"]:
        if debug:
            print(f"Getting cert from {connhost}")
        if int(port) != 25:
            certobj = getcerthttps(connhost, port)
        else:
            certobj = getsmtpcert(connhost, port)
        printcertinfo(certobj, hostname, port, args['--info'])

    cloudflare_loaded = checkcloudflare()

    if args["--cloudflare"] or args["cloudflare"]:
        if cloudflare_loaded:
            cf = CloudFlare.CloudFlare(debug=debug)
            zones = getcfzoneinfo(cf, zonename)
            zone = zones[0]
            if not zones:
                print("Not managed by cloudflare. Bailing.")
                return -1
            if args["--info"]:
                print(">>> Cloudflare Information:")
                print(f"Zone name: {zonename}")
                print(f"Zone ID: {zone['id']}")
                print(f"Zone owner: {zone['owner']['email']}")
                print(f"Name servers: {zone['name_servers']}")

            if not args['--dryrun']:
                createcftlsa(cf, zone['name'], zone['id'], hostname, port, getcertpubhash(certobj))

        else:
            print("Please install the cloudflare module for this to work.")
            return -1

    if args['verify']:
        # What's in DNS?
        rr = gettlsa(zonename, hostname, port)
        # What does the server report:
        certobj = None
        if int(port) != 25:
            certobj = getcerthttps(connhost, port)
        else:
            certobj = getsmtpcert(connhost, port)
        hosthash = getcertpubhash(certobj)
        dnshash = rr.to_text().split()[3]
        if hosthash == dnshash:
            print("OK - TLSA is valid")
            return 0
        else:
            print(f"ERROR - TLSA invalid: {hosthash} != {dnshash}")
            return 2




    if args['file']:
        certobj = getcertfile(args['<certfile>'])
        printcertinfo(certobj, port, args['--info'])



if __name__ == '__main__':
    sys.exit(main())
