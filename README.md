# GenTLSA

Simple tool for dealing with DANE/TSLA records. Also displays info for certificates. Also has optional CloudFlare support. 

## Usage
```
./gentlsa.py

Usage:
    gentlsa.py generate <zone> <port> [--hostname <shorthost>] [--info] [--cloudflare] [--dryrun]
    gentlsa.py verify <name> <port>
    gentlsa.py cloudflare [--info] [--listzones]
    gentlsa.py file <certfile>
```

### Example output:

Generating TLSA entry:

```
┌─[ekollof@elrond]─(~/Code/gentlsa)(master U:2 ?:1 ✗)
└─[15:39]-(%)-[$] ./gentlsa.py generate coolvibe.org 443
_443._tcp TLSA 3 1 1 8adbc769e05014c8e0b431770f97e1f09659c5a6eae9f5683701bc6f071d8a94
```
Display cert info:
```
┌─[ekollof@elrond]─(~/Code/gentlsa)(master S:4 U:3 ?:1 ✗)
└─[15:47]-(%)-[$] ./gentlsa.py generate coolvibe.org 443 --info
>>> Certificate Information:
Serial : 4906ded898ec441cbbc223acb960a95239a
Issuer : C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3
Subject: CN=coolvibe.org
Subject Alternative Name(s): DNS:coolvibe.org
Certificate Inception:  2018-08-26 09:00:32+00:00 UTC
Certificate Expiration: 2018-11-24 09:00:32+00:00 UTC
_443._tcp TLSA 3 1 1 8adbc769e05014c8e0b431770f97e1f09659c5a6eae9f5683701bc6f071d8a94

```
Update Cloudflare entry (will create an entry if not present). Will only return the TLSA record and report if Cloudflare
registration worked. This is an example which uses STARTTLS to get the certificate.
```
┌─[ekollof@elrond]─(~/Code/gentlsa)(master U:1 ?:1 ✗)
└─[15:43]-(%)-[$] ./gentlsa.py generate hackerheaven.org 25 --hostname mx --cloudflare --info  
>>> Certificate Information:
Serial : 4c44f405bf6ea521edd60e9ad9806df051a
Issuer : C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3
Subject: CN=mx.hackerheaven.org
Subject Alternative Name(s): DNS:mx.hackerheaven.org
Certificate Inception:  2018-09-01 03:16:37+00:00 UTC
Certificate Expiration: 2018-11-30 03:16:37+00:00 UTC
_25._tcp.mx TLSA 3 1 1 e4a76ab909941a470314f4a4fcc9338623dd619ab9f5ac715a08fe9b94417d8c
>>> Cloudflare Information:
Zone name: hackerheaven.org
Zone ID: REDACTED
Zone owner: REDACTED
Name servers: ['isla.ns.cloudflare.com', 'jake.ns.cloudflare.com']
Cloudflare: TLSA record updated for hackerheaven.org
```


## TODO:

* Check if DANE/TLSA is valid
* Make more configurable and suitable to run from cron(1)

 


