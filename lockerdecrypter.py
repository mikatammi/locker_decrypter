#!/usr/bin/env python

import untangle
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import bytes_to_long
from base64 import b64decode
import io
from struct import unpack
import sys
import os

from rijndael import rijndael
from cbc import zeropad, cbc


class DecryptError(Exception):
    pass


def decrypt_file(encrypted_filename, decrypted_filename, rsa_cipher):
    with open(encrypted_filename, 'rb') as encrypted_file:
        # Get the file size by seeking into end
        encrypted_file.seek(0, io.SEEK_END)
        file_size = encrypted_file.tell()

        # Some checks
        encrypted_file.seek(0)
        if 0 != encrypted_file.tell() or file_size < 4:
            raise DecryptError()

        header_size = unpack('I', encrypted_file.read(4))[0]
        
        if header_size > file_size:
            raise DecryptError()

        # Read and decrypt header
        header = encrypted_file.read(header_size)
        
        try:
            decrypted_header = cipher.decrypt(header)
        except:
            raise DecryptError()

        # Read initialization vector and key from header
        aes_iv_length = unpack('I', decrypted_header[0:4])[0]
        aes_iv_start = 4
        aes_iv = decrypted_header[aes_iv_start:aes_iv_start + aes_iv_length]
        aes_key_length_start = aes_iv_start + aes_iv_length
        aes_key_length = unpack('I', 
            decrypted_header[aes_key_length_start:aes_key_length_start + 4])[0]
        aes_key_start = aes_key_length_start + 4
        aes_key = decrypted_header[aes_key_start:aes_key_start + aes_key_length]

        # Read encrypted file into memory
        ciphertext = encrypted_file.read()

        # Initialize cipher and crypto-block-chain
        rjn_cipher = rijndael(aes_key, 32)
        padding = zeropad(32)
        cbc_cipher = cbc(padding, rjn_cipher, aes_iv)

        # Decrypt the file
        decrypted_ct = cbc_cipher.decrypt(ciphertext)

        with open(decrypted_filename, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_ct)


def decrypt_directory(directory_to_decrypt, rsa_cipher):
    for root, dirs, filenames in os.walk(directory_to_decrypt):
        for filename in filenames:
            # Construct full filepath
            full_filepath = os.path.join(root, filename)
            full_filepath_decrypted = full_filepath + '.decrypted'

            # Try to decrypt the file
            try:
                decrypt_file(full_filepath, full_filepath_decrypted, rsa_cipher)
                os.rename(full_filepath, full_filepath + '.orig')
                os.rename(full_filepath_decrypted, full_filepath)
                print(full_filepath + ' decrypted')
            except DecryptError:
                print(full_filepath + ' could not decrypt')


if __name__ == "__main__":

    if len(sys.argv) < 3:
        sys.exit("Usage: %s <private_key.xml> <directory_to_decrypt>" % sys.argv[0])

    private_key_xml_filename = sys.argv[1]
    directory_to_decrypt = sys.argv[2]

    # Parse XML file containing private key components
    priv_key_dom = untangle.parse(private_key_xml_filename)

    # Get private key components from XML
    n = priv_key_dom.RSAKeyValue.Modulus.cdata
    e = priv_key_dom.RSAKeyValue.Exponent.cdata
    d = priv_key_dom.RSAKeyValue.D.cdata

    # Decode base64 RSA components and convert them from bytes to big integer
    rsa_components = tuple(map(bytes_to_long, map(b64decode, (n, e, d))))

    # Construct RSA Key object
    rsa_key = RSA.construct(rsa_components)

    # Construct new PCKS1_OAEP cipher using the RSA key
    cipher = PKCS1_OAEP.new(rsa_key)

    decrypt_directory(directory_to_decrypt, cipher)
