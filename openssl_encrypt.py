#!/usr/bin/env python

# This whole script taken heavily from https://gist.github.com/thwarted/1024558#file-sshpub-to-rsa

import os
import sys
import base64
import subprocess
from zipfile import ZipFile
from tempfile import NamedTemporaryFile, TemporaryFile

ENCRYPTED_KEY_NAME = "key.enc"
ENCRYPTED_FILE_SUFFIX = ".encrypted"


# We're working under the assumption that we will only be encrypting relatively small plain text info,
# so in the interest of ease of use we're going to try something kind of stupid and embed the binary data *within*
# the decrpyt script, Which is itself a part of the encrypt script. Let's see how it goes...
EMBEDDED_BINARY_DATA = None


def execute_command(command, stdin=False):
    """
    A general purpose helper function for running commands and getting back the value from stdin
    :param command: Command you want to run
    :param stdin: Whether or not to wait for input
    :return: The stdout from the command
    """
    if stdin:
        proc = subprocess.Popen(command.split(), stdout=subprocess.PIPE, stdin=sys.stdin)
        proc.wait()
    else:
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

    import struct
    from pyasn1.type import univ
    from pyasn1.codec.der import encoder as der_encoder

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


def encrypt(public_info, infile):
    """
    Decrypts the input file using the public information
    :param public_info: String of OpenSSL public key information
    :param infile: Filename of the file to encrypt
    :return: A temporary file containing the zip info
    """
    keyfields = public_info.split()
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
    encrypt_file.write(
        execute_command("openssl enc -aes-256-cbc -salt -in %s -pass file:%s" % (infile, encrypt_key.name)))
    encrypt_file.close()

    # Bundle all the needed assets into a zip
    _bundle = TemporaryFile(mode='r+')
    with ZipFile(_bundle, mode='w') as zf:
        zf.write(encrypt_key.name, ENCRYPTED_KEY_NAME)
        zf.write(encrypt_file.name, os.path.basename(infile + ENCRYPTED_FILE_SUFFIX))

    # Cleanup temp files
    os.remove(pem.name)
    os.remove(key.name)
    os.remove(encrypt_file.name)
    os.remove(encrypt_key.name)

    return _bundle


def decrypt(priv_key):
    _bundle = TemporaryFile()
    _bundle.write(base64.b64decode(EMBEDDED_BINARY_DATA))
    _bundle.seek(0)
    with ZipFile(_bundle, mode='r') as zf:

        encrypt_file = None
        filename = None
        for name in zf.namelist():
            if name.endswith(ENCRYPTED_FILE_SUFFIX):
                encrypt_file = NamedTemporaryFile(delete=False)
                encrypt_file.write(zf.read(name))
                encrypt_file.close()
                filename = name.replace(ENCRYPTED_FILE_SUFFIX, '')
                break
        if not encrypt_file:
            sys.stderr.write("Unable to find encrypted file\n")
            sys.exit(1)

        # Get the decrypted key
        encrypt_key = NamedTemporaryFile(delete=False)
        encrypt_key.write(zf.read(ENCRYPTED_KEY_NAME))
        encrypt_key.close()

        key = NamedTemporaryFile(delete=False)
        key.write(execute_command('openssl rsautl -decrypt -inkey %s -in %s' %
                                  (os.path.expanduser(priv_key), encrypt_key.name)))
        key.close()

        # Finally, decrypt the actual file
        print "Writing to file: %s" % filename
        with open(filename, 'w+') as outfile:
            outfile.write(execute_command('openssl enc -d -aes-256-cbc -in %s -pass file:%s' %
                                          (encrypt_file.name, key.name)))

        # Cleanup temporary files
        os.remove(encrypt_file.name)
        os.remove(encrypt_key.name)
        os.remove(key.name)

if __name__ == "__main__":

    arg_length = len(sys.argv) - 1  # Subtract 1 for the implicit first argument, the programs name

    if not EMBEDDED_BINARY_DATA:
        # We are not using an autogenerated file embedded with binary data so we're doing an encryption
        if arg_length > 3 or arg_length < 2:
            sys.stderr.write("Usage:\n" +
                             "\t%s [OpenSSL public key file] [input file] [output file]\n" % sys.argv[0] +
                             "\techo '[OpenSSL public key]' | %s [input file] [output file]\n" % sys.argv[0])
            sys.exit(1)

        # Create a zipfile containing all the encrypted info and the info needed to decrypt
        if arg_length == 3:
            # The public key was passed to us as a file
            public = open(os.path.expanduser(sys.argv[1])).read()
            input = os.path.expanduser(sys.argv[2])
            output = os.path.expanduser(sys.argv[3])
        else:
            # Try to get the public key from stdin
            public = sys.stdin.readline()
            input = os.path.expanduser(sys.argv[1])
            output = os.path.expanduser(sys.argv[2])

        bundle = encrypt(public, input)
        bundle.seek(0)
        # Now with the encrypted bundle created, let's open up *this* file and embed it in
        with open(sys.argv[0], 'r') as this_file:
            with open(output, 'w') as embedded:
                for line in this_file:
                    if line.strip() == 'EMBEDDED_BINARY_DATA = None':
                        bundle.seek(0)
                        embedded.write('EMBEDDED_BINARY_DATA = "%s"\n' % base64.b64encode(bundle.read()))
                    else:
                        embedded.write(line)

        os.chmod(output, 0777)
        bundle.close()

    else:
        # We're using a file that was autogenerated and has embedded data so we're decrypting
        if arg_length > 1:
            sys.stderr.write("Usage:\n" +
                             "\t%s\n" % sys.argv[0] +
                             "\t%s [OpenSSL private key (defaults to ~/.ssh/id_rsa)]\n" % sys.argv[0])
            sys.exit(1)

        if arg_length:
            decrypt(priv_key=sys.argv[1])
        else:
            decrypt(priv_key='~/.ssh/id_rsa')