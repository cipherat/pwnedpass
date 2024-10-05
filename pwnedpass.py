#!/usr/bin/env python3

import requests
import hashlib
import argparse

API = "https://api.pwnedpasswords.com/range/"

parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
    description="pwnedpass - Check if your password is leaked [version 1.0]",
    epilog="**This program does not send your full hash neither the password in plain text to the API**\n"
           "Note: when using -D with the program `jq`, replace single-quote with double-quote, or `jq` will raise an error.\n" \
           "Example:\n\tuser@home:~$ pwnedpass -D $PASSWORD | tr \"'\" '\"' | jq")
parser.add_argument("password", metavar="Password", type=str, help="check if the password is leaked.")
parser.add_argument("-D", "--dictionary", action="store_true", help="only print database. (note*: hash signature won't be shown)")
parser.add_argument("-v", "--verbose", action="store_true", help="print extra data.")
args = parser.parse_args()

user_password = args.password
size = 5

sha1_password = hashlib.sha1()
sha1_password.update(user_password.encode())
sha1_hex = sha1_password.hexdigest().upper()
hash_sign = sha1_hex[:size-len(sha1_hex):].upper()
hash_body = sha1_hex[len(hash_sign)::].upper()

req = requests.get(API + hash_sign)
dataset = req.text
hash_table = dict(couple.split(":") for couple in dataset.split("\r\n"))

if args.dictionary:
    print(hash_table)
    exit(0)

if args.verbose:
    print("Plain Password: %s" % user_password)
    print("Full SHA1 Hash: %s" % sha1_hex)
    print("Hash Signature: %s" % hash_sign)
    print("Hash Body: %s" % hash_body)
    print("Found: %s" % hash_table.get(hash_body))

if hash_table.get(hash_body) is not None:
    times_used = hash_table.get(hash_body)
    print("The Password \"%s\" Was Found %s Times." % (user_password, times_used))
else:
    print("You're All Good, Nothing Found.")
