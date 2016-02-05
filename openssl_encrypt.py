
import sys
import base64
import struct
from pyasn1.type import univ
from pyasn1.codec.der import encoder as der_encoder


def openssl_pub_to_pem(keydata):
    """
    Converts an OpenSSL public key to a PEM format. Taken from https://gist.github.com/thwarted/1024558#file-sshpub-to-rsa
    :param keydata: OpenSSL public key
    :return: the PEM formatted key data
    """

    keydata = base64.b64decode(keydata)

    parts = []
    while keydata:
        # read the length of the data
        dlen = struct.unpack('>I', keydata[:4])[0]

        # read in <length> bytes
        data, keydata = keydata[4:dlen+4], keydata[4+dlen:]

        parts.append(data)

    e_val = eval('0x' + ''.join(['%02X' % struct.unpack('B', x)[0] for x in parts[1]]))
    n_val = eval('0x' + ''.join(['%02X' % struct.unpack('B', x)[0] for x in parts[2]]))

    bitstring = univ.Sequence()
    bitstring.setComponentByPosition(0, univ.Integer(n_val))
    bitstring.setComponentByPosition(1, univ.Integer(e_val))

    bitstring = der_encoder.encode(bitstring)

    bitstring = ''.join([('00000000'+bin(ord(x))[2:])[-8:] for x in list(bitstring)])

    bitstring = univ.BitString("'%s'B" % bitstring)

    pubkeyid = univ.Sequence()
    pubkeyid.setComponentByPosition(0, univ.ObjectIdentifier('1.2.840.113549.1.1.1')) # == OID for rsaEncryption
    pubkeyid.setComponentByPosition(1, univ.Null(''))

    pubkey_seq = univ.Sequence()
    pubkey_seq.setComponentByPosition(0, pubkeyid)
    pubkey_seq.setComponentByPosition(1, bitstring)

    value = "%s\n%s\n%s" % ("-----BEGIN PUBLIC KEY-----",
                            base64.encodestring(der_encoder.encode(pubkey_seq)),
                            "-----END PUBLIC KEY-----")

    return value


if __name__ == "__main__":
    pass