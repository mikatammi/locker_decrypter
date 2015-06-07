Locker Decrypter
================


License
-------
Public domain


What is this about?
-------------------

Locker is probably one of the worst malware which exists as of today. It is
variant of Cryptolocker family of malware, and so called ransomware, which
encrypts victim's important files (such as photos and documents) based on file
extension.

I had to rescue files from computer infected by this pesky Locker-malware, and
since there were no proper Linux-tools to decrypt the files, I decided to write
one.

On May 30th, this kind of document appeared in pastebin:
http://pastebin.com/1WZGqrUH

The document describes the format used in the encrypted files so that one can
decrypt the files, assuming that the encryption key is known.

Also a 100MB+ csv-file containing all the RSA-keypairs and bitcoin addresses
for ransom payments was posted to
https://mega.co.nz/#!W85whbSb!kAb-5VS1Gf20zYziUOgMOaYWDsI87o4QHJBqJiOW6Z4


Dependencies
------------

This tool requires Python 2 (tested with 2.7, Python 3 does not work as someone
would need to port the rijndael.py).

- untangle
- pycrypto


How to decrypt my files
-----------------------

First you have to dig either RSA public key or Bitcoin address from vitcim's
computer. The files containing relevant information typically reside in
C:\ProgramData\rkcl directory.

* data.aa0 - Contains list of encrypted files
* data.aa6 - Contains the bitcoin address
* data.aa7 - Contains the public key

Use either RSA public key or Bitcoin address to find the private key from the
csv-file referred above and to save it to file private\_key.xml:

    grep [BITCOIN ADDRESS HERE] database_dump.csv | sed -e 's/.*,.*,//g' > private_key.xml

Then run the tool in a directory where you want to decrypt your files:

    lockerdecrypter.py <private_key.xml> <directory_to_decrypt>

The tool automatically tries to determine which of the files were actually
encrypted and which were not.


Credits
-------

I couldn't find any good library implementation of Rijndael for Python so first
I have to give credit to Bram Cohen for Rijndael reference implementation I
used implementing this. I also quite deliberately took the example class
implementing crypto-block-chain from this stackoverflow post:
http://stackoverflow.com/questions/8356689/python-equivalent-of-phps-mcrypt-rijndael-256-cbc
