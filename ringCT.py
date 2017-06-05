from secp256k1 import * 
import struct
import random
import hashlib
import binascii
import ecdsa
from ecdsa import SigningKey, VerifyingKey

MAX_AMOUNT = 2**64;
MAX_MIXIN = 100; 
crv=ecdsa.SECP256k1
P = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
G = "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
curveOrder = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"

def getPublicKeys(number):
    # TODO
    return False

def hashPublicKey(pubK):
    return to_int_from_bytes(hashlib.sha256(pubK).digest())

def to_32_bytes_number (val, endianness='big'):
    # see https://stackoverflow.com/questions/8730927/convert-python-long-int-to-fixed-size-byte-array/28057222
    fmt = '%%0%dx' % 64
    s = binascii.unhexlify(fmt % val)
    if endianness == 'little':
        # see http://stackoverflow.com/a/931095/309233
        s = s[::-1]
    return s

def to_int_from_bytes(val, endianness= 'big'):
    return int.from_bytes(val, byteorder=endianness)

def pedersen(m, r):
    return (pow(g,m,p)*pow(h,r,p))%p


def ecdhEncode(mask, amount, receiverPk): 
    sendPriv = SigningKey.generate(curve=crv)
    recvPubKey = VerifyingKey.from_sec(receiverPk, curve=crv)
    # sharedSecret = recvPubKey.ecdh(bytes.fromhex(sendPriv.serialize()))
    # sharedSecretInt = int.from_bytes(sharedSecret, byteorder='big')
    # #overlow ??
    sharedSecretInt = 0
    newMask = mask + sharedSecretInt
    newAmount = amount + sharedSecretInt
    return newMask, newAmount, sendPriv

def ecdhDecode(mask, amount, senderPk, receiverSk): 
    priv = SigningKey.generate(curve=crv)
    priv.from_string(receiverSk, curve=crv)
    # sharedSecret = PublicKey(pubkey=senderPk, raw=True).ecdh(bytes.fromhex(priv.serialize()))
    # sharedSecretInt = int.from_bytes(sharedSecret, byteorder='big')
    sharedSecretInt = 0
    newMask = mask - sharedSecretInt
    newAmount = amount - sharedSecretInt
    return newMask, newAmount

def prepareMG(pubsK, pubsC, inSk, outSk, outPk, outC, index):
    #pubs is a matrix of ctkeys [P, C] 
    #inSk is the keyvector of [x, mask] secret keys
    #outMasks is a keyvector of masks for outputs
    #outPk is a list of output ctkeys [P, C]
    #index is secret index of where you are signing (integer)
    #returns a list (mgsig) [ss, cc, II] where ss is keymatrix, cc is key, II is keyVector of keyimages

    rowsQ = len(pubs)
    colsM = len(pubs[0])

    matrix = [[0 for x in range(colsM + 1)] for y in range(rowsQ)]
    sumCOut = 0
    for i in range(rowsQ):
        sumCOut += outC[i]
    for i in range(rowsQ):
        for j in range(colsM):
            matrix[i][j] = pubsK[i][j]

        matrix[i][colsM]  = -sumCOut
        for j in range(colsM):
            matrix[i][colsM]  += pubsC[1][j]


    genMG("", matrix, sk, index)

def list_pubK_object_to_bytes(list):
    ret = list[0]
    for x in range(1, len(list)):
        ret += list[x]
    return ret

def genMG(message, matrix, sk, index):
    m = len(matrix)
    n = len(matrix[0])
    print(n)
    print(m)
    message_bytes = bytes(message, 'UTF-8')
    alpha = [None for x in range(m)]
    
    L = [[None for x in range(m)] for y in range(n)] 
    R = [[None for x in range(m)] for y in range(n)] 
    I = [None for x in range(m)]

    for j in range(0, m):
        alpha[j] = to_32_bytes_number(random.randrange(P))
        g = SigningKey.generate(curve=crv)
        L[index][j] = g.from_string(alpha[j], curve=crv).to_string()

        print(bytes.hex(sk[j]))
        skJ = g.from_string((sk[j]), curve=crv)
        print(hashPublicKey(matrix[index][j]))
        print(sk[j])
        skJHashPub = skJ.verifying_key.pubkey.point * hashPublicKey(matrix[index][j])
        I[j] = VerifyingKey.from_public_point(skJHashPub, curve=crv).to_sec()
        print(I[j])

        alphaKey = g.from_string(alpha[j], curve=crv)
        alphaHashPub = alphaKey.verifying_key.pubkey.point * hashPublicKey(matrix[index][j])
        R[index][j] = VerifyingKey.from_public_point(alphaHashPub, curve=crv).to_sec()


    print(L[index])
    print(R[index])
    c_idx_1 = hashlib.sha3_256(message_bytes + list_pubK_object_to_bytes(L[index]) + list_pubK_object_to_bytes(R[index])).digest();
    

    print("----------------\n Good For me \n ***********")


    ss = [[None for x in range(m)] for y in range(n)]
    c = c_idx_1
    c_0 = None
    for i in range(1, n): 
        idx = (index + i) % n
        print(idx)
        for j in range(0, m):
            ss[idx][j] = to_32_bytes_number(random.randrange(P))

            pubK = PublicKey(pubkey = matrix[index][j], raw = True).tweak_mul(c)
            tmp = generator.tweak_mul(ss[idx][j])
            tmp.combine([pubK.deserialize(pubK.serialize())])
            L[idx][j] = tmp.serialize()
            tmp = PrivateKey(privkey=bytes.fromhex(bytes.hex(ss[idx][j])), raw=True)
            R[idx][j] = tmp.tweak_mul(hashPublicKey(matrix[index][j]))
            c_I = I[j].tweak_mul(c)
            x = PublicKey.combine(pubkeys=[c_I, R[idx][j]])

        c = hashlib.sha3_256(message_bytes + list_pubK_object_to_bytes(L[idx]) + list_pubK_object_to_bytes(R[idx])).digest();
        if idx == 0:
            c_0 = c


    for j in range(0, m):
        ss[index][j] = to_32_bytes_number((to_int_from_bytes(alpha[j]) - to_int_from_bytes(c) * to_int_from_bytes(sk[j])) % to_int_from_bytes(bytes.fromhex(curveOrder)))
        sjG = generator.tweak_mul(ss[index][j])
        tmp2 = PublicKey(pubkey=matrix[index][j], raw=True)
        cjPj = tmp2.tweak_mul(c)
        sjG.combine([cjPj.deserialize(cjPj.serialize())])
        print(bytes.hex(sjG.serialize()))
        Lj = generator.tweak_mul(alpha[j])
        print(bytes.hex(Lj.serialize()))

def createTransaction(privateKey, publicKey, destinations, amounts, mixin):
    if(mixin < 0 or mixin > MAX_MIXIN):
        print("The number of ring participant should be between 0 and " + str(MAX_MIXIN) + "\n Aborting...")
        return False
    try:
        privkey = PrivateKey(privkey=privateKey, raw=True)
        pubkey = privkey.pubkey;
        assert pubkey.serialize() == PublicKey(pubkey=publicKey, raw=True).serialize()
    except AssertionError:
        print("Derived public key: " + bytes.hex(privkey.pubkey.serialize()))
        print("Provied public key: " + bytes.hex(PublicKey(pubkey=publicKey, raw=True).serialize()))
        print("The provided public key doesn't match the private key.\n Aborting...")
    except Exception:
        print("The private key is not in the right format.\n\
            The format is either a compressed key as a string of 33 hex or an uncompresed key as a string of 65 hex.\n\
            Aborting...")
        return False

    if(len(destinations) != len(amounts) or mixin != len(amounts)):
        print("The mixin number should match the number of outputs addresses and the number of outputs amounts.\n Aborting...")
        return False

    destPubKeys = []
    for i in range (0, len(destinations)):
        try:
            destPubKeys.append(PublicKey(pubkey=destinations[i], raw=True))
        except Exception:
            print("The public key #" + str(i) + " is not in the right format.\n\
                The format is either a compressed key as a string of 33 hex or an uncompresed key as a string of 65 hex.\n\
                Aborting...")
    for i in range (0, len(amounts)):
        if(amounts[i] < 0 or amounts[i] > MAX_AMOUNT):
            print("The amount #" + str(i) + " should be between 0 and " + str(MAX_AMOUNT) + "\n Aborting...")
            return False



    

def test():
    for i in range(0, 10):
        x = random.randrange(P)
        y = random.randrange(P)
        newMask, newAmount, sendPubKey = ecdhEncode(x, y, bytes.fromhex(pub))
        newX, newY = ecdhDecode(newMask, newAmount, sendPubKey, bytes.fromhex(pri))
        assert newX == x and newY == y, "ECDH failed, x = %d, y = %d" % (x, y)

    for i in range(0, 10):
        x = random.randrange(2**256)
        assert x == to_int_from_bytes(to_32_bytes_number(x)), "bytes <-> int conversion failed, x = %d" % (x)
pri = "07ca500a843616b48db3618aea3e9e1174dede9b4e94b95b2170182f632ad47c"
pri4 = "79d3372ffd4278affd69313355d38c6d90d489e4ab0bbbef9589d7cc9559ab6d"
pri5 = "00dff8928e99bda9bb83a377e09c8bf5d110c414fa65d771b7b84797709c7dd0b1"
pub = "0462abcca39e6dbe30ade7be2949239311162792bdb257f408ccd9eab65e18bc5bbcf8a3f08675bd792251a23d09a48a870644ba3923996cc5b5ec2d68043f3df3"
pub2 = "040ccad48919d8f6a206a1ac7113c22db62aa744a0700762b70aa0284d474c00203029637ce8e84f6551fd92a0db8e1f964ff13aa992e4cbfd1fb8fa33c6e6c53c"
pub3 = "049f742f925b554e2dc02e2da5cb9663ef810e9eefb30818b3c12bc26afb8dd7ba3461c0f7d2b997bf455973af308a71ed34ae415cfc946de84db3961db522e5d2"
pub4 = "04ef36c6d140e7970cc54c08e0e5d3173059ee6276dd0de99e09d10c49bd49e63c44e0a2e7180fff5e3e8a549027b8a37bc3a9437374ef1b7a05040b244a7bccc5"
pub5 = "04da11a42320ae495014dd9c1c51d43d6c55ca51b7fe9ae3e1258e927e97f48be4e7a4474c067154fdaa1c5b26dee555c3e649337605510cf9e1d5c1e657352e9c"
# createTransaction(bytes.fromhex(pri), bytes.fromhex(pub), [bytes.fromhex(pub2), bytes.fromhex(pub3)], [1, 2], 2)

# newMask, newAmount, sendPubKey = ecdhEncode(1,2,bytes.fromhex(pub))
# print(bytes.hex(newMask))
# print(bytes.hex(newAmount))

# ecdhDecode(newMask, newAmount, sendPubKey, bytes.fromhex(pri))

# test()
print(bytes.fromhex(pri4))
genMG(message="hello", 
    matrix=[[bytes.fromhex(pub2), bytes.fromhex(pub), bytes.fromhex(pub3)], [bytes.fromhex(pub3), bytes.fromhex(pub4), bytes.fromhex(pub5)]], 
    sk=[bytes.fromhex(pri4), bytes.fromhex(pri)], index=1)

