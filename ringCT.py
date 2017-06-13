from secp256k1 import * 
import struct
import random
import hashlib
import binascii
import ecdsa
from ecdsa import SigningKey, VerifyingKey
from six import b
import time


from ethjsonrpc import EthJsonRpc
from ethjsonrpc.constants import BLOCK_TAGS, BLOCK_TAG_EARLIEST, BLOCK_TAG_LATEST

MAX_AMOUNT = 2**64;
MAX_MIXIN = 100; 
crv=ecdsa.SECP256k1
P = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
G = "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
curveOrder = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"

connection = EthJsonRpc('localhost', 8545)
contractAddress = "0xd87c13c2677756af2436155e8250f17e3b5038b0" 

def getPublicKeys(number):
    # TODO
    return False

def hashPublicKey(pubK):
    return to_int_from_bytes(hashlib.sha256(pubK).digest())

def hash_to_point(pubK):
    g = SigningKey.generate(curve=crv)
    return g.from_string(hashlib.sha256(pubK).digest(), curve=crv).verifying_key

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

def to_hex_list_list(list):
    l = []
    for i in range(0, len(list)):
        ll = []
        for j in range(0, len(list[i])):
            ll.append("0x"+bytes.hex(list[i][j]))
        l.append(ll)
    return l

def to_hex_list(list):
    l = []
    for i in range(0, len(list)):
        l.append("0x"+bytes.hex(list[i]))
    return l

def pedersen(m, r):
    return (pow(g,m,p)*pow(h,r,p))%p

# def create_contract():
#     compiled = "60606040527f79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817986000557f483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b860015560406040519081016040528060005481526020016001548152506002906002610076929190610120565b5060206040519081016040528060026002806020026040519081016040528092919082600280156100bc576020028201915b8154815260200190600101908083116100a8575b505050505081525060046000820151816000019060026100dd929190610160565b5050507ffffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f600655600560075560066008556007600955341561011b57fe5b6101c5565b826002810192821561014f579160200282015b8281111561014e578251825591602001919060010190610133565b5b50905061015c91906101a0565b5090565b826002810192821561018f579160200282015b8281111561018e578251825591602001919060010190610173565b5b50905061019c91906101a0565b5090565b6101c291905b808211156101be5760008160009055506001016101a6565b5090565b90565b610890806101d46000396000f30060606040526000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680637422d36414610046578063ecd31f60146102e9575bfe5b341561004e57fe5b610166600480803590602001908201803590602001908080601f0160208091040260200160405190810160405280939291908181526020018383808284378201915050505050509190803590602001908201803590602001908080601f016020809104026020016040519081016040528093929190818152602001838380828437820191505050505050919080359060200190919080359060200190820180359060200190808060200260200160405190810160405280939291908181526020016000905b82821015610158578484839050604002016002806020026040519081016040528092919082600260200280828437820191505050505081526020019060010190610113565b5050505050919050506104b5565b604051808060200180602001858152602001806020018481038452888181518152602001915080519060200190808383600083146101c3575b8051825260208311156101c35760208201915060208101905060208303925061019f565b505050905090810190601f1680156101ef5780820380516001836020036101000a031916815260200191505b50848103835287818151815260200191508051906020019080838360008314610237575b80518252602083111561023757602082019150602081019050602083039250610213565b505050905090810190601f1680156102635780820380516001836020036101000a031916815260200191505b508481038252858181518152602001915080516000925b818410156102d3578284906020019060200201516002602002808383600083146102c3575b8051825260208311156102c35760208201915060208101905060208303925061029f565b505050905001926001019261027a565b9250505097505050505050505060405180910390f35b34156102f157fe5b6104b3600480803590602001908201803590602001908080601f016020809104026020016040519081016040528093929190818152602001838380828437820191505050505050919080359060200190919080359060200190919080359060200190820180359060200190808060200260200160405190810160405280939291908181526020016000905b828210156103c157848483905060400201600280602002604051908101604052809291908260026020028082843782019150505050508152602001906001019061037c565b50505050509190803560001916906020019091908035906020019091908035906020019091908035906020019082018035906020019080806020026020016040519081016040528093929190818152602001838360200280828437820191505050505050919080359060200190919080359060200190820180359060200190808060200260200160405190810160405280939291908181526020016000905b828210156104a5578484839050604002016002806020026040519081016040528092919082600260200280828437820191505050505081526020019060010190610460565b5050505050919050506106c9565b005b6104bd61083c565b6104c561083c565b60006104cf610850565b7f551303dd5f39cbfe6daba6b3e27754b8a7d72f519756a2cde2b92c2bbde159a76040518080602001828103825260138152602001807f2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d0000000000000000000000000081525060200191505060405180910390a17f43123f7005ece31cd2478fa2cd0bec5ea2e353c1c3fe9ca390a6de2ab917eac96040518080602001828103825260168152602001807f576520676f742061206e696365206d6573736167653a0000000000000000000081525060200191505060405180910390a17f43123f7005ece31cd2478fa2cd0bec5ea2e353c1c3fe9ca390a6de2ab917eac9886040518080602001828103825283818151815260200191508051906020019080838360008314610610575b805182526020831115610610576020820191506020810190506020830392506105ec565b505050905090810190601f16801561063c5780820380516001836020036101000a031916815260200191505b509250505060405180910390a17f43123f7005ece31cd2478fa2cd0bec5ea2e353c1c3fe9ca390a6de2ab917eac96040518080602001828103825260138152602001807f2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d0000000000000000000000000081525060200191505060405180910390a18787878793509350935093505b945094509450949050565b6000600088518a8c02141515610768577f551303dd5f39cbfe6daba6b3e27754b8a7d72f519756a2cde2b92c2bbde159a760405180806020018281038252602b8152602001807f4d69736d6174636820696e207468652064696d656e73696f6e206f662074686581526020017f206b6579206d617472697800000000000000000000000000000000000000000081525060400191505060405180910390a15b7f43123f7005ece31cd2478fa2cd0bec5ea2e353c1c3fe9ca390a6de2ab917eac98c60405180806020018281038252838181518152602001915080519060200190808383600083146107d9575b8051825260208311156107d9576020820191506020810190506020830392506107b5565b505050905090810190601f1680156108055780820380516001836020036101000a031916815260200191505b509250505060405180910390a1600090505b8381101561082d575b8080600101915050610817565b5b505050505050505050505050565b602060405190810160405280600081525090565b6020604051908101604052806000815250905600a165627a7a72305820a5fa078f0f18cb8426d0c3bc94628d48f90145b19b0de014beb6764f4c00e7ca0029"
#     blockNumber = connection.eth_blockNumber()
#     contract_tx = connection.create_contract(connection.eth_coinbase(), compiled, gas=300000)
#     print("tx " + contract_tx)
#     contract_addr = connection.eth_getTransactionReceipt(contract_tx)
#     while(contract_addr == None):
#         print("waiting")
#         time.sleep(0.5)
#         contract_addr = connection.eth_getTransactionReceipt(contract_tx)
#     global contractAddress
#     contractAddress = connection.get_contract_address(contract_tx)
#     print("addre" + contractAddress)

def send_ring(message, pubkey, c0, ss, II):
    print("------ Preparing to send transaction  -------")
    filterNames = ['Log Error', 'Print string', 'Print bool', 'Print address', 'Print uint256']
    to_keccack = ["LogErrorString(string)", "PrintString(string)", "PrintBool(bool)", "PrintAddress(address)", "PrintUint(uint256)"]
    keccack = []
    for i in range(0, len(to_keccack)):
        keccack.append(connection.web3_sha3(to_keccack[i]))

    filter = []
    for i in range(0, len(keccack)):
        filter.append(connection.eth_newFilter(from_block='earliest', address=contractAddress, topics=[keccack[i]]))

    pubkeysAlligned = []
    for i in range(0, len(pubkey)):
        for j in range(0, len(pubkey[0])):
            pk = VerifyingKey.from_sec(pubkey[i][j]).pubkey.point
            pubkeysAlligned.append([to_32_bytes_number(pk.x()), to_32_bytes_number(pk.y())])

    ssAlligned = []
    for i in range(0, len(ss)):
        for j in range(0, len(ss[0])):
            ssAlligned.append(ss[i][j])

    IIAlligned = []
    for i in range(0, len(II)):
        I = VerifyingKey.from_sec(II[i]).pubkey.point
        IIAlligned.append([to_32_bytes_number(I.x()), to_32_bytes_number(I.y())])

    # print(to_hex_list_list(pubkeysAlligned))
    # print("-----------")
    # print(to_hex_list(IIAlligned))
    # print("-----------")
    # print(to_hex_list_list(ssAlligned))


    #function testb(string message, uint256 pkX, uint256 pkY, bytes32[2][] pkB, bytes32 c0, uint256 ssX, uint256 ssY, bytes32[] ssB, uint256 IIX, bytes32[2][] IIB) returns (bool)
    results = connection.call_with_transaction(connection.eth_coinbase(), contractAddress, 
        # function signature
        'testb(string,uint256,uint256,bytes32[2][],bytes32,uint256,uint256,bytes32[],uint256,bytes32[2][])',\
        [message,\
        len(pubkey), len(pubkey[0]), pubkeysAlligned,\
        c0,\
        len(ss), len(ss[0]), ssAlligned, \
        len(II), IIAlligned], gas=900000000)

    print("------Transaction sent, waiting events-------")
    time.sleep(5)

    for i in range(0, len(filter)):
        change = connection.eth_getFilterChanges(filter[i])
        if len(change) > 0:
            for j in range(0, len(change)):
                print(filterNames[i] + " result " + str(j) + ":\n" + str(bytes.fromhex(change[j]["data"][2:].replace('00', ''))))

    print("------ All events have benn displayed -------")


def ecdhEncode(mask, amount, receiverPk): 
    # mask: the mask to hide (32 bytes number)
    # amount: the amount to hide (32 bytes number)
    # receiverPk: the receiver pk (sec format)
    ## return: newMask: hidden mask (32 bytes number)
    ##         newAmount: hidden amount (32 bytes number)
    ##         senderPk: the public key genereated by the sender to encode this amount (sec format)
    g = SigningKey.generate(curve=crv)
    secret = to_32_bytes_number(random.randrange(crv.order))
    senderSk= g.from_string(secret, curve=crv)
    senderPk = senderSk.verifying_key
    recvPubKey = VerifyingKey.from_sec(receiverPk, curve=crv)
    to_hash = VerifyingKey.from_public_point(recvPubKey.pubkey.point * to_int_from_bytes(secret), curve=crv).to_sec()
    sharedSecretInt = to_int_from_bytes(hashlib.sha256((to_hash)).digest())
    # #TODO overlow ??
    newMask = (to_int_from_bytes(mask) + sharedSecretInt) % crv.order
    newAmount = (to_int_from_bytes(amount) + sharedSecretInt) % crv.order
    return  to_32_bytes_number(newMask), to_32_bytes_number(newAmount), senderPk.to_sec()

def ecdhDecode(mask, amount, senderPk, receiverSk): 
    # counter method to ecdh encode
    # mask: the hidden mask (32 bytes number)
    # amount: the hidden amount (32 bytes number)
    # senderPk: the public key genereated by the sender to encode this amount (sec format)
    # receiverSk: the receiver sk (32 bytes number)
    ## return: newMask: unhidden mask (32 bytes number)
    ##         newAmount: unhidden amount (32 bytes number)
    sendPubKey = VerifyingKey.from_sec(senderPk, curve=crv)
    to_hash = VerifyingKey.from_public_point(sendPubKey.pubkey.point * to_int_from_bytes(receiverSk), curve=crv).to_sec()
    sharedSecretInt = to_int_from_bytes(hashlib.sha256((to_hash)).digest())
    newMask = (to_int_from_bytes(mask) - sharedSecretInt) % crv.order
    newAmount = (to_int_from_bytes(amount) - sharedSecretInt) % crv.order
    return to_32_bytes_number(newMask), to_32_bytes_number(newAmount)

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

    #TODO message

    return genMG("", matrix, sk, index)

def list_to_bytes(list):
    ret = list[0]
    for x in range(1, len(list)):
        ret += list[x]
    return ret

def genMG(message, matrix, sk, index):

    n = len(matrix)
    assert n > 0, "No public key received."
    m = len(matrix[0])
    assert m == len(sk), "The number of secret key doesn't match the number of public key."

    for i in range(0, n):
        assert len(matrix[i]) == m, "Public key array is not rectangular."
    assert m > 0, "No public key in the array."
    assert index >= 0 and index < m, "Not a valid index."
    

    message_bytes = bytes(message, 'UTF-8')

    g = SigningKey.generate(curve=crv)

    for i in range(0, m):
        assert g.from_string(sk[i], curve=crv).verifying_key.to_sec(compressed=False) == matrix[index][i], "One secret key doesn't match the public key."

    print("------ Done with checking private key -------")

    alpha = [None for x in range(m)]
    I = [None for x in range(m)]
    ss = [[None for x in range(m)] for y in range(n)]
    
    L = [[None for x in range(m)] for y in range(n)] 
    R = [[None for x in range(m)] for y in range(n)] 


    for j in range(0, m):
        skJHashPub_point = hash_to_point(matrix[index][j]).pubkey.point * to_int_from_bytes(sk[j])
        I[j] = VerifyingKey.from_public_point(skJHashPub_point, curve=crv).to_sec()
 
        alpha[j] = to_32_bytes_number(random.randrange(crv.order))
        L[index][j] = g.from_string(alpha[j], curve=crv).verifying_key.to_sec()

        alphaHashPub_point = hash_to_point(matrix[index][j]).pubkey.point * to_int_from_bytes(alpha[j])
        R[index][j] = VerifyingKey.from_public_point(alphaHashPub_point, curve=crv).to_sec()


    c_idx_1 = hashlib.sha3_256(message_bytes + list_to_bytes(L[index]) + list_to_bytes(R[index])).digest()



    c = c_idx_1
    c_0 = None
    for i in range(1, n): 
        idx = (index + i) % n
        for j in range(0, m):
            # assert ss[idx][j] == None, "Hmm sounds bad"
            ss[idx][j] = to_32_bytes_number(random.randrange(crv.order))

            c_PubK = VerifyingKey.from_sec(matrix[idx][j], curve=crv).pubkey.point * to_int_from_bytes(c)
            sj_G = g.from_string(ss[idx][j], curve=crv)
            L_point = c_PubK + sj_G.verifying_key.pubkey.point
            L[idx][j] = VerifyingKey.from_public_point(L_point, curve=crv).to_sec()


            c_I = VerifyingKey.from_sec(I[j], curve=crv).pubkey.point * to_int_from_bytes(c)
            R_point = hash_to_point(matrix[idx][j]).pubkey.point * to_int_from_bytes(ss[idx][j]) + c_I
            R[idx][j] = VerifyingKey.from_public_point(R_point, curve=crv).to_sec()

        c = hashlib.sha3_256(message_bytes + list_to_bytes(L[idx]) + list_to_bytes(R[idx])).digest();
        if idx == n-1:
            c_0 = c


    L_tmp = [None for x in range(m)]
    R_tmp = [None for x in range(m)]

    for j in range(0, m):
        ss[index][j] = to_32_bytes_number((to_int_from_bytes(alpha[j]) - to_int_from_bytes(c) * to_int_from_bytes(sk[j])) % crv.order)

        c_PubK = VerifyingKey.from_sec(matrix[index][j], curve=crv).pubkey.point * to_int_from_bytes(c)
        sj_G = g.from_string(ss[index][j], curve=crv)
        L_point = c_PubK + sj_G.verifying_key.pubkey.point
        L_tmp[j] = VerifyingKey.from_public_point(L_point, curve=crv).to_sec()

        c_I = VerifyingKey.from_sec(I[j], curve=crv).pubkey.point * to_int_from_bytes(c)
        R_point = hash_to_point(matrix[index][j]).pubkey.point * to_int_from_bytes(ss[index][j]) + c_I
        R_tmp[j] = VerifyingKey.from_public_point(R_point, curve=crv).to_sec()

    # sanity check:
    c_tmp = hashlib.sha3_256(message_bytes + list_to_bytes(L_tmp) + list_to_bytes(R_tmp)).digest()
    assert L_tmp == L[index] and R_tmp == R[index] and c_tmp == c_idx_1, "Sanity check for computing ss[index] failed."
    print("------ Done with generating the MLSAG -------")

    assert verifyMG(message, matrix, I, c_0, ss), "Ring verification failed."
    print("------ Done with verifying the MLSAG  -------")
    return I, c_0, ss

def verifyMG(message, matrix, I, c_0, ss):
    n = len(ss)
    assert n > 0, "No ss in the ring signature. Length = 0."
    m = len(ss[0])
    for i in range(0, n):
        assert len(ss[i]) == m, "Non rectangular ss in the ring signature."
    assert m > 0, "No ss in the ring siganture. Length ss[0] = 0"
    assert len(I) == len(ss[0]), "Not the same number of pubkey hash (I) as of secret (ss)."

    message_bytes = bytes(message, 'UTF-8')

    g = SigningKey.generate(curve=crv)

    L = [[None for x in range(m)] for y in range(n)] 
    R = [[None for x in range(m)] for y in range(n)] 

    c = c_0
    for idx in range(0, n): 
        for j in range(0, m):
            c_PubK = VerifyingKey.from_sec(matrix[idx][j], curve=crv).pubkey.point * to_int_from_bytes(c)
            sj_G = g.from_string(ss[idx][j], curve=crv)
            L_point = c_PubK + sj_G.verifying_key.pubkey.point
            L[idx][j] = VerifyingKey.from_public_point(L_point, curve=crv).to_sec()

            c_I = VerifyingKey.from_sec(I[j], curve=crv).pubkey.point * to_int_from_bytes(c)
            R_point = hash_to_point(matrix[idx][j]).pubkey.point * to_int_from_bytes(ss[idx][j]) + c_I
            R[idx][j] = VerifyingKey.from_public_point(R_point, curve=crv).to_sec()

        c = hashlib.sha3_256(message_bytes + list_to_bytes(L[idx]) + list_to_bytes(R[idx])).digest();

    return c == c_0


def createTransaction(publicKey, privateKey, destinations, amounts, mixin):
    # publicKey: vector of public keys corresponding to the owner inputs(sec format)
    # privateKey: vector of private keys corresponding to the public keys (format 32bytes number aka to_string() output)
    # destinations: vector of public keys (sec format)
    # amounts: vector of the different amounts going to the respective destinations public keys (int)
    # mixin: the number of pk to get involved in the rings (int)
    ## return: destinations: a vector of destiantions public keys as received (sec format)
    ##         destinationsCommitment: a vector of commitment assigned to each destinations public keys (32 bytes numbers)
    ##         I: part of MLSAG, a vector of pk in sec format corresponding the the sha256 hash of the sender pk 
    ##         c_0: part of MLSAG, first sha3_256 (keccak) of the consecutive series of the MLSAG 
    ##         ss: part of MLSAG, a matrix of "random" 32 bytes number
    ##         infos: an array of ecdhEncode result containing the amount paid to the corresponding output pk
    ##         rangeSig: vector of rangeSig (format TODO)

    assert mixin < MAX_MIXIN and mixin > 0, "The number of ring participant should be between 0 and " + str(MAX_MIXIN) + "\n Aborting..."
    assert len(privateKey) == len(publicKey), "The number of private key doesn't match the number of public key"
    assert len(destinations) == len(amounts), \
        "The number of outputs addresses should match the number of outputs amounts.\n\
        Aborting..."
    outNum = len(amounts)
    for i in range (0, outNum):
        assert amounts[i] > 0 and amounts[i] < MAX_AMOUNT, \
            "The amount #" + str(i) + " should be between 0 and " + str(MAX_AMOUNT) + "\n\
            Aborting..."

    m = len(privateKey)
    g = SigningKey.generate(curve=crv)


    for i in range(0, m):
        assert g.from_string(privateKey[i], curve=crv).verifying_key.to_sec(compressed=False) == publicKey[i], "One secret key doesn't match the public key."

        # print("The private key is not in the right format.\n\
            # The format is either a compressed key as a string of 33 hex or an uncompresed key as a string of 65 hex.\n\
            # Aborting...")
    inSkMasks = [] 
    inPkMasks = [] 
    for i in range(0,m):
        secret = to_32_bytes_number(random.randrange(crv.order))
        inSkMasks.append(secret)
        inPkMasks.append(g.from_string(secret, curve=crv).verifying_key.to_string())


    destinationsCommitment = []
    infos = []
    rangeSig = []
    for i in range(0, outNum):

        outCommit, outSkMask, rg = proveRange(amounts[i])
        destinationsCommitment.append(outCommit)
        rangeSig.append(rg)
        hiddenMask, hiddenAmount, senderPk = ecdhEncode(outSkMask, to_32_bytes_number(amounts[i]), destinations[i])
        infos.append([hiddenMask, hiddenAmount, senderPk])

    pkMatrix, pkMasksMatrix, index = populateFromBlockchain(publicKey, inPkMasks, mixin)

    I, c_0, ss = prepareMG(pkMatrix, pkMasksMatrix, privateKey, inSkMasks, destinations, destinationsCommitment, index)

    return destinations, destinationsCommitment, I, c_0, ss, infos, rangeSig

def populateFromBlockchain(publicKey, inPkMasks, mixin):
    # publicKey: vector of pk, sec format
    # inPkMasks: vector of bytes32 (format from verifyingkey.to_stirng())
    # mixin: number of other pk involved, int
    ## return: pk matrix (format sec), 
    ##         coressponding masks matrix, 
    ##         index of our pks in the matrix

    assert len(publicKey) == len(inPkMasks), "Mismatch in the number of public key and their corresponding mask"
    m = len(publicKey)
    index = random.randrange(mixin - 1)
    pkMatrix = []
    maskMatrix = []
    for i in range(0, mixin):
        if i != index:
            pkMatrix.append([getKeyFromBlockchain() for i in range(0, m)])
            maskMatrix.append([to_32_bytes_number(random.randrange(crv.order)) for i in range(0, m)])
        else: 
            pkMatrix.append(publicKey)
            maskMatrix.append(inPkMasks)
    return pkMatrix, maskMatrix, index

def getKeyFromBlockchain():
    #TODO
    ## return: a public key "from the blockchain" in the to_sec format
    g = SigningKey.generate(curve=crv)
    x = to_32_bytes_number(random.randrange(crv.order))
    return g.from_string(x).verifying_key.to_sec()

def proveRange(amount):
    #TODO
    # amount: the amount to prove range from
    ## return: an output commitment (sum of ci) (32 bytes), 
    ##         a mask (32 bytes),
    ##         the actual range signature
    rg = 1
    return to_32_bytes_number(random.randrange(crv.order)), to_32_bytes_number(random.randrange(crv.order)), rg

def test():
    print("------  Entering the first test case. -------")

    for i in range(0, 10):
        x = random.randrange(2**256)
        assert x == to_int_from_bytes(to_32_bytes_number(x)), "bytes <-> int conversion failed, x = %d" % (x)
    
    print("------ Entering the second test case. -------")

    for i in range(0, 10000):
        x = random.randrange(crv.order)
        y = random.randrange(crv.order)
        newMask, newAmount, sendPubKey = ecdhEncode(to_32_bytes_number(x), to_32_bytes_number(y), bytes.fromhex(pub))
        newX, newY = ecdhDecode(newMask, newAmount, sendPubKey, bytes.fromhex(pri))
        assert to_int_from_bytes(newX) == x and to_int_from_bytes(newY) == y, "ECDH failed, x = %d, y = %d" % (x, y)

    print("------  All test passed. Well done !  -------")


def test2():
    c = EthJsonRpc('127.0.0.1', 8080)
    print(c.net_version())
    print(c.web3_clientVersion())
    print(c.eth_gasPrice())
    print(c.eth_blockNumber())
    contractAddress = "0xa8b4b6546394a808e24a168de6c0a5ea227545b4" 
    u = c.eth_newFilter(from_block='earliest', address=contractAddress, topics=[])
            
    print("-----u------")
    print(u)

 #function testb(string message, uint256 pkX, uint256 pkY, bytes32[2][] pkB, bytes32 c0, uint256 ssX, uint256 ssY, bytes32[] ssB, uint256 IIX, bytes32[2][] IIB) returns (bool)
    results = c.call_with_transaction(c.eth_coinbase(), contractAddress, 
        # function signature
        'set_s(string)',\
        ["hello"]
        # ,['bool']\
        ) #return type
    bn = c.eth_blockNumber()
    print(bn)
    print(results)
    while(c.eth_blockNumber() == bn):
        print(c.eth_blockNumber())
        print("waiting for deploy")
        time.sleep(0.5)
    while(c.eth_blockNumber() == bn+1):
        print(c.eth_blockNumber())
        print("waiting for event")
        time.sleep(0.5)
    vv = c.eth_getFilterChanges(u)
    print("vv"+str(vv)+str(c.eth_blockNumber()))

pri = "07ca500a843616b48db3618aea3e9e1174dede9b4e94b95b2170182f632ad47c"
pri4 = "79d3372ffd4278affd69313355d38c6d90d489e4ab0bbbef9589d7cc9559ab6d"
pri5 = "00dff8928e99bda9bb83a377e09c8bf5d110c414fa65d771b7b84797709c7dd0b1"
pub = "0462abcca39e6dbe30ade7be2949239311162792bdb257f408ccd9eab65e18bc5bbcf8a3f08675bd792251a23d09a48a870644ba3923996cc5b5ec2d68043f3df3"
pub2 = "040ccad48919d8f6a206a1ac7113c22db62aa744a0700762b70aa0284d474c00203029637ce8e84f6551fd92a0db8e1f964ff13aa992e4cbfd1fb8fa33c6e6c53c"
pub3 = "049f742f925b554e2dc02e2da5cb9663ef810e9eefb30818b3c12bc26afb8dd7ba3461c0f7d2b997bf455973af308a71ed34ae415cfc946de84db3961db522e5d2"
pub4 = "04ef36c6d140e7970cc54c08e0e5d3173059ee6276dd0de99e09d10c49bd49e63c44e0a2e7180fff5e3e8a549027b8a37bc3a9437374ef1b7a05040b244a7bccc5"
pub5 = "04da11a42320ae495014dd9c1c51d43d6c55ca51b7fe9ae3e1258e927e97f48be4e7a4474c067154fdaa1c5b26dee555c3e649337605510cf9e1d5c1e657352e9c"
# createTransaction(bytes.fromhex(pri), bytes.fromhex(pub), [bytes.fromhex(pub2), bytes.fromhex(pub3)], [1, 2], 2)


# with open("contractAddress.txt") as f:
#     content = f.readlines()
# # you may also want to remove whitespace characters like `\n` at the end of each line
# content = [x.strip() for x in content]
# found = False
# i = -1
# while not found:
#     i += 1
#     if content[i][0:7] == 'RingCT:':
#         found = True
#         contractAddress = content[i][8:50]


# create_contract()
# print("c"+contractAddress)
# test()
# test2()
matrix=[[bytes.fromhex(pub2), bytes.fromhex(pub3)], \
        [bytes.fromhex(pub), bytes.fromhex(pub4)],\
        [bytes.fromhex(pub3), bytes.fromhex(pub5)]]
# test2()
# I, c_0, ss = genMG(message="hello2", matrix=matrix, \
#     sk=[bytes.fromhex(pri), bytes.fromhex(pri4)], index=1)
# print("-----I-----")
# print(I)
# print("-----c-----")
# print(c_0)
# print("-----ss-----")
# print(ss)
I = [b'\x02l:\x9e\xfce\xba\x89\x0e\xb3\x08m-\x89\xa6\xa1\x0c\xafM\xbe\xc5\x86\xf3_c\xafj\xfaCw\xa5j\xf8', b'\x03\x94\xda\xdcp0t\xbb\x98J\xb8\xb8\x92\xa7A\x81u"\xb0\x91M\x14\xc5\x0b\xb7\t\x1c\xc1\xdfVpL\xd1']
c_0 = b'\xdd\x05\xa2\x83f\xf7\x9dDfE\xb4\xeb\xbb(\x8d\xa4\xfc\x01\xb6B\xfa\xba\x12\xf5\xecGb\x16\x0e|\xbc\xee'
ss= [[b'\xe5\xd6\xbc\x1c\xceX#\x0fv\xf6\xd9O\xcb~i\x93\x8f\x9dz\x0c\xa5\xe8\x13\x80g=C\x81\x8b\xf8Jq', b'\x11\xf36q\x86\xf1]E\xedy\x18\xa3lH\xb8\xbd[\x87\x15\xb8\x1f\xec\xce\xd7\x04\xa5q\xdc\x1a>\x80\xd0'], [b'm\xda\x9d\r\xc9?\xf9=\xd0\xd5\xa5dyT\x9c)3\xcc\xe6X.\x9f\\\x07\xb5\x87\x935\xe2t\xf1\xc9', b'6\xac\x1dA\x8c\x8e\xe6\xa4\xf8`\xd6\x7f{jg\xb4#1\x8aA\x8e\xa1TpM\xc8~\xed\xecV\x9f\x9f'], [b'\xb6&}o"\xb8\x07]\xc3\x1c\xf6[K0\xf8\x85PN\xdf\xe1\xf3\x9e\xf4\x16S.\x8ba{\x92\xf1X', b'\x92x\xbe\x97\xbfK\x9c:\x81^\xea\xac\xbcC~\xc7\xc6\xdc\xfa\xf4*\xc7\x0e\xd8?\xb3\x8d\x8dFL\xf6\xfe']]
# send_ring("The ring message", matrix, c_0, ss, I)

# test()
createTransaction([bytes.fromhex(pub), bytes.fromhex(pub4)], [bytes.fromhex(pri), bytes.fromhex(pri4)], [bytes.fromhex(pub), bytes.fromhex(pub5)], [1,2], 2)