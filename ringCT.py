from secp256k1 import * 
import struct
import random
import hashlib
import binascii

MAX_AMOUNT = 2**64;
MAX_MIXIN = 100; 
P = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
G = "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
def getPublicKeys(number):
    # TODO
    return False

def to_32_bytes_number (val, endianness='big'):
    fmt = '%%0%dx' % (256 // 4)
    s = binascii.unhexlify(fmt % val)
    if endianness == 'little':
        # see http://stackoverflow.com/a/931095/309233
        s = s[::-1]
    return s

def pedersen(m, r):
    return (pow(g,m,p)*pow(h,r,p))%p


def ecdhEncode(mask, amount, receiverPk): 
    sendPriv = PrivateKey()
    recvPubKey = PublicKey(pubkey=receiverPk, raw=True)
    sharedSecret = recvPubKey.ecdh(bytes.fromhex(sendPriv.serialize()))
    sharedSecretInt = int.from_bytes(sharedSecret, byteorder='big')
    #overlow ??
    newMask = mask + sharedSecretInt
    newAmount = amount + sharedSecretInt
    return newMask, newAmount, sendPriv.pubkey.serialize()

def ecdhDecode(mask, amount, senderPk, receiverSk): 
    priv = PrivateKey(privkey=receiverSk, raw=True)
    sharedSecret = PublicKey(pubkey=senderPk, raw=True).ecdh(bytes.fromhex(priv.serialize()))
    sharedSecretInt = int.from_bytes(sharedSecret, byteorder='big')
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

def genMG(message, matrix, sk, index):
    n = len(matrix)
    message_bytes = bytes(message, 'UTF-8')
    alpha = to_32_bytes_number(random.randrange(P))
    s = [];
    for i in range(0, n):
        s.append(to_32_bytes_number(random.randrange(P)))

    generator = PublicKey(pubkey=bytes.fromhex(G), raw=True)
    Lj = generator.tweak_mul(alpha)
    hashed = bytes.hex(hashlib.sha256(matrix[index]).digest())
    hashed = "02"+hashed
    tmp = PublicKey(pubkey=bytes.fromhex(hashed), raw=True)
    I = tmp.tweak_mul(sk)
    Rj = tmp.tweak_mul(alpha)
    cj_1 = hashlib.sha3_256(message_bytes + (Lj.serialize()) + (Rj.serialize())).digest();
    c = cj_1
    c1 = None
    for i in range(1, n):
        idx = (index + i) % n
        print(idx)
        x = PublicKey(pubkey = matrix[idx], raw = True).tweak_mul(c)
        y = generator.tweak_mul(s[idx])
        y.combine([x.deserialize(x.serialize())])
        L_idx = y
        hashed = bytes.hex(hashlib.sha256(matrix[idx]).digest())
        hashed = "02"+hashed
        tmp = PublicKey(pubkey=bytes.fromhex(hashed), raw=True)
        x = I.tweak_mul(c)
        z = tmp.tweak_mul(s[idx])
        z.combine([x.deserialize(x.serialize())])
        R_idx = z
        c = hashlib.sha3_256(message_bytes + (L_idx.serialize()) + (R_idx.serialize())).digest();
        if idx == 0:
            c1 = c

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

pri = "07ca500a843616b48db3618aea3e9e1174dede9b4e94b95b2170182f632ad47c"
pub = "0462abcca39e6dbe30ade7be2949239311162792bdb257f408ccd9eab65e18bc5bbcf8a3f08675bd792251a23d09a48a870644ba3923996cc5b5ec2d68043f3df3"
pub2 = "040ccad48919d8f6a206a1ac7113c22db62aa744a0700762b70aa0284d474c00203029637ce8e84f6551fd92a0db8e1f964ff13aa992e4cbfd1fb8fa33c6e6c53c"
pub3 = "049f742f925b554e2dc02e2da5cb9663ef810e9eefb30818b3c12bc26afb8dd7ba3461c0f7d2b997bf455973af308a71ed34ae415cfc946de84db3961db522e5d2"
createTransaction(bytes.fromhex(pri), bytes.fromhex(pub), [bytes.fromhex(pub2), bytes.fromhex(pub3)], [1, 2], 2)

newMask, newAmount, sendPubKey = ecdhEncode(1,2,bytes.fromhex(pub))
# print(bytes.hex(newMask))
# print(bytes.hex(newAmount))

ecdhDecode(newMask, newAmount, sendPubKey, bytes.fromhex(pri))
print(to_32_bytes_number(2))

genMG("hello", [bytes.fromhex(pub2), bytes.fromhex(pub), bytes.fromhex(pub3)], bytes.fromhex(pri), 1)
test()

