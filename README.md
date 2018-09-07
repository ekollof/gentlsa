# GenTLSA

Simple tool for dealing with TSLA records. Also displays info for certificates. Also has optional CloudFlare support. 

## Usage
```
./gentlsa.py
Usage:
    gentlsahash.py host <name> <port> [--info] [--cloudflare] [--dryrun]
    gentlsahash.py cloudflare [--info] [--listzones]
    gentlsahash.py file <certfile>
```

### Example output:

Generating TLSA entry:

```
┌─[ekollof@elrond]─(~/Code/gentlsa)(master U:2 ?:1 ✗)
└─[15:39]-(%)-[$] ./gentlsahash.py host coolvibe.org 443
_443._tcp TLSA 3 1 1 8adbc769e05014c8e0b431770f97e1f09659c5a6eae9f5683701bc6f071d8a94
```
Display cert info:
```
┌─[ekollof@elrond]─(~/Code/gentlsa)(master S:4 U:3 ?:1 ✗)
└─[15:47]-(%)-[$] ./gentlsahash.py host coolvibe.org 443 --info
>>> Certificate Information:
Serial : 4906ded898ec441cbbc223acb960a95239a
Issuer : C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3
Subject: CN=coolvibe.org
Subject Alternative Name(s): DNS:coolvibe.org
Certificate Inception:  2018-08-26 09:00:32+00:00 UTC
Certificate Expiration: 2018-11-24 09:00:32+00:00 UTC
_443._tcp TLSA 3 1 1 8adbc769e05014c8e0b431770f97e1f09659c5a6eae9f5683701bc6f071d8a94

```

## TODO:

* Finalize Cloudflare support (apply TLSA record to zone root, assuming a webserver lives there)
* Check if DANE/TLSA is valid
* Support mail hosts/STARTTLS/AUTH TLS/etc
* Make more configurable and suitable to run from cron(1)

 


