# This whole script taken heavily from https://gist.github.com/thwarted/1024558#file-sshpub-to-rsa

import os
import sys
import base64
import struct
import subprocess
from zipfile import ZipFile
from pyasn1.type import univ
from pyasn1.codec.der import encoder as der_encoder
from tempfile import NamedTemporaryFile, TemporaryFile


ENCRYPTED_KEY_NAME    = "key.enc"
ENCRYPTED_FILE_SUFFIX = ".encrypted"


def execute_command(command):
    """
    A general purpose helper function for running commands and getting back the value from stdin
    :param command:
    :return:
    """
    proc = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
    value = proc.communicate()[0]
    if proc.returncode:
        sys.stderr.write("Could not execute command: %s" % command)
        sys.exit(1)
    return value


def openssl_pub_to_pem(keydata):
    """
    Converts an OpenSSL public key to a PEM format.
    :param keydata: OpenSSL public keydata
    :return: the PEM formatted key data
    """

    keydata = base64.b64decode(keydata)

    parts = []
    while keydata:
        # read the length of the data
        dlen = struct.unpack('>I', keydata[:4])[0]

        # read in <length> bytes
        data, keydata = keydata[4:dlen + 4], keydata[4 + dlen:]

        parts.append(data)

    e_val = eval('0x' + ''.join(['%02X' % struct.unpack('B', x)[0] for x in parts[1]]))
    n_val = eval('0x' + ''.join(['%02X' % struct.unpack('B', x)[0] for x in parts[2]]))

    bitstring = univ.Sequence()
    bitstring.setComponentByPosition(0, univ.Integer(n_val))
    bitstring.setComponentByPosition(1, univ.Integer(e_val))

    bitstring = der_encoder.encode(bitstring)

    bitstring = ''.join([('00000000' + bin(ord(x))[2:])[-8:] for x in list(bitstring)])

    bitstring = univ.BitString("'%s'B" % bitstring)

    pubkeyid = univ.Sequence()
    pubkeyid.setComponentByPosition(0, univ.ObjectIdentifier('1.2.840.113549.1.1.1'))  # == OID for rsaEncryption
    pubkeyid.setComponentByPosition(1, univ.Null(''))

    pubkey_seq = univ.Sequence()
    pubkey_seq.setComponentByPosition(0, pubkeyid)
    pubkey_seq.setComponentByPosition(1, bitstring)

    value = "%s\n%s%s" % ("-----BEGIN PUBLIC KEY-----",
                            base64.encodestring(der_encoder.encode(pubkey_seq)),
                            "-----END PUBLIC KEY-----")

    return value


def decrypt(public, infile):
    """
    Decrypts the input file using the public information
    :param public: String of OpenSSL public key information
    :param infile: Filename of the file to encrypt
    :return: A temporary file containing the zip info
    """
    keyfields = public.split()
    if len(keyfields) == 3:
        # We don't actually need nor want the comment
        keyfields.pop()
    if len(keyfields) != 2:
        sys.stderr.write("Invalid public key format\n")
        sys.exit(1)

    keyformat, keydata = keyfields
    if keyformat != "ssh-rsa":
        sys.stderr.write("Key type does not appear to be ssh-rsa")
        sys.exit(1)

    pem = NamedTemporaryFile(delete=False)
    pem.write(openssl_pub_to_pem(keydata))
    pem.close()

    # Generate random key for encryption
    key = NamedTemporaryFile(delete=False)
    key.write(execute_command("openssl rand -base64 32"))
    key.close()

    # Encrypt the random key
    encrypt_key = NamedTemporaryFile(delete=False)
    encrypt_key.write(execute_command("openssl rsautl -encrypt -inkey %s -pubin -in %s" % (pem.name, key.name)))
    encrypt_key.close()

    # Encrypt the actual file
    encrypt_file = NamedTemporaryFile(delete=False)
    encrypt_file.write(execute_command("openssl enc -aes-256-cbc -salt -in %s -pass file:%s" % (infile, encrypt_key.name)))
    encrypt_file.close()

    # Bundle all the needed assets into a zip
    zip_file = TemporaryFile()
    with ZipFile(zip_file) as zf:
        zf.write(encrypt_key, ENCRYPTED_KEY_NAME)
        zf.write(encrypt_file, infile+ENCRYPTED_FILE_SUFFIX)

    # Cleanup temp files
    os.remove(pem.name)
    os.remove(key.name)
    os.remove(encrypt_file)
    os.remove(encrypt_key)

    return zip_file

if __name__ == "__main__":

    arg_length = len(sys.argv) - 1  # Subtract 1 for the implicit first argument, the programs name
    if arg_length > 3 or arg_length < 2:
        sys.stderr.write("Usage:\n" +
                         "\t%s encrypt [OpenSSL public key file] [input file]\n" % sys.argv[0] +
                         "\techo '[OpenSSL public key]' | %s encrypt [input file]\n" % sys.argv[0] +
                         "\t%s decrypt [input file]\n" % sys.argv[0] +
                         "\t%s decrypt [OpenSSL private key file] [input file]\n" % sys.argv[0])
        sys.exit(1)

    if sys.argv[1] == 'encrypt':
        if arg_length == 3:
            # The public key was passed to us as a file
            public = open(os.path.expanduser(sys.argv[2])).read()
            input = os.path.expanduser(sys.argv[3])
        else:
            # Try to get the public key from stdin
            public = sys.stdin.readline()
            input = os.path.expanduser(sys.argv[2])

        decrypt(public, input)

    elif sys.argv[1] == 'decrypt':
        pass