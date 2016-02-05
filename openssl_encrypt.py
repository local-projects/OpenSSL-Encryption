import os
import sys
import base64
import struct
from pyasn1.type import univ
from pyasn1.codec.der import encoder as der_encoder


def openssl_pub_to_pem(keydata):
    """
    Converts an OpenSSL public key to a PEM format. Taken from https://gist.github.com/thwarted/1024558#file-sshpub-to-rsa
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

    value = "%s\n%s\n%s" % ("-----BEGIN PUBLIC KEY-----",
                            base64.encodestring(der_encoder.encode(pubkey_seq)),
                            "-----END PUBLIC KEY-----")

    return value


def decrypt(public, input):
    """
    Decrypts the input file using the public information
    :param public: String of OpenSSL public key information
    :param input: File object pointing to the file to encrypt
    :return:
    """
    pass


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
            input = open(os.path.expanduser(sys.argv[3]))
        else:
            # Try to get the public key from stdin
            public = sys.stdin.readline()
            input = open(os.path.expanduser(sys.argv[2]))

        decrypt(public, input)

    elif sys.argv[1] == 'decrypt':
        pass