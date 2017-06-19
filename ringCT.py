from secp256k1 import * 
import struct
import random
import hashlib
import sha3
import binascii
import ecdsa
from ecdsa import SigningKey, VerifyingKey
from six import b
from ecdsa.ellipticcurve import CurveFp, INFINITY, Point
import time


from ethjsonrpc import EthJsonRpc
from ethjsonrpc.constants import BLOCK_TAGS, BLOCK_TAG_EARLIEST, BLOCK_TAG_LATEST

debug = True
MAX_AMOUNT = 2**64;
MAX_MIXIN = 100; 
crv=ecdsa.SECP256k1
g = SigningKey.generate(curve=crv)
P = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
G = "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
curveOrder = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"

connection = EthJsonRpc('localhost', 8545)
contractAddress = "0xa7b1800d46dd564278053eeb06cbdfdce3798c98" 
ATOMS = 64

def hash_to_point(pubK):
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

def add_2_32b(a, b):
    return to_32_bytes_number((to_int_from_bytes(a) + to_int_from_bytes(b)) % crv.order)

def sub_2_32b(a, b):
    return to_32_bytes_number((to_int_from_bytes(a) - to_int_from_bytes(b)) % crv.order)

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
            pk = VerifyingKey.from_string(pubkey[i][j]).pubkey.point
            pubkeysAlligned.append([to_32_bytes_number(pk.x()), to_32_bytes_number(pk.y())])

    ssAlligned = []
    for i in range(0, len(ss)):
        for j in range(0, len(ss[0])):
            ssAlligned.append(ss[i][j])

    IIAlligned = []
    for i in range(0, len(II)):
        I = VerifyingKey.from_string(II[i]).pubkey.point
        IIAlligned.append([to_32_bytes_number(I.x()), to_32_bytes_number(I.y())])


    # def to_hex_list_list(list):
    #     l = []
    #     for i in range(0, len(list)):
    #         ll = []
    #         for j in range(0, len(list[i])):
    #             ll.append("0x"+bytes.hex(list[i][j]))
    #         l.append(ll)
    #     return l
        
    # def to_hex_list(list):
    #     l = []
    #     for i in range(0, len(list)):
    #         l.append("0x"+bytes.hex(list[i]))
    #     return l
    # print(to_hex_list_list(pubkeysAlligned))
    # print("-----------")
    # print(to_hex_list(IIAlligned))
    # print("-----------")
    # print(to_hex_list_list(ssAlligned))


    #function testb(string message, uint256 pkX, uint256 pkY, bytes32[2][] pkB, bytes32 c0, uint256 ssX, uint256 ssY, bytes32[] ssB, uint256 IIX, bytes32[2][] IIB) returns (bool)
    cb = connection.eth_coinbase()
    print(cb)
    results = connection.call_with_transaction(cb, contractAddress, 
        # function signature
        'testb(string,uint256,uint256,bytes32[2][],bytes32,uint256,uint256,bytes32[],uint256,bytes32[2][])',\
        [message,\
        len(pubkey), len(pubkey[0]), pubkeysAlligned,\
        c0,\
        len(ss), len(ss[0]), ssAlligned, \

        len(II), IIAlligned], gas=99999999999, gas_price=1)
    
    bashCommand = 'wget 127.0.0.1:8545 --background --post-data ' + results.replace(" ", "")
    import subprocess
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    print(output)
    print(results)
    print("------Transaction sent, waiting events-------")
    time.sleep(180)

    for i in range(0, len(filter)):
        change = connection.eth_getFilterChanges(filter[i])
        if len(change) > 0:
            for j in range(0, len(change)):
                print(filterNames[i] + " result " + str(j) + ":\n" + str(bytes.fromhex(change[j]["data"][2:].replace('00', ''))))

    print("------ All events have been displayed -------")


def ecdhEncode(mask, amount, receiverPk): 
    # mask: the mask to hide (32 bytes number)
    # amount: the amount to hide (32 bytes number)
    # receiverPk: the receiver pk (sec format)
    ## return: newMask: hidden mask (32 bytes number)
    ##         newAmount: hidden amount (32 bytes number)
    ##         senderPk: the public key genereated by the sender to encode this amount (sec format)

    secret = to_32_bytes_number(random.randrange(crv.order))
    senderSk= g.from_string(secret, curve=crv)
    senderPk = senderSk.verifying_key
    recvPubKey = VerifyingKey.from_string(receiverPk, curve=crv)
    to_hash = VerifyingKey.from_public_point(recvPubKey.pubkey.point * to_int_from_bytes(secret), curve=crv).to_string()
    sharedSecretInt = to_int_from_bytes(hashlib.sha256((to_hash)).digest())
    newMask = (to_int_from_bytes(mask) + sharedSecretInt) % crv.order
    newAmount = (to_int_from_bytes(amount) + sharedSecretInt) % crv.order
    return  to_32_bytes_number(newMask), to_32_bytes_number(newAmount), senderPk.to_string()

def ecdhDecode(mask, amount, senderPk, receiverSk): 
    # counter method to ecdh encode
    # mask: the hidden mask (32 bytes number)
    # amount: the hidden amount (32 bytes number)
    # senderPk: the public key genereated by the sender to encode this amount (sec format)
    # receiverSk: the receiver sk (32 bytes number)
    ## return: newMask: unhidden mask (32 bytes number)
    ##         newAmount: unhidden amount (32 bytes number)

    sendPubKey = VerifyingKey.from_string(senderPk, curve=crv)
    to_hash = VerifyingKey.from_public_point(sendPubKey.pubkey.point * to_int_from_bytes(receiverSk), curve=crv).to_string()
    sharedSecretInt = to_int_from_bytes(hashlib.sha256((to_hash)).digest())
    newMask = (to_int_from_bytes(mask) - sharedSecretInt) % crv.order
    newAmount = (to_int_from_bytes(amount) - sharedSecretInt) % crv.order
    return to_32_bytes_number(newMask), to_32_bytes_number(newAmount)

def createTransaction(inPk, inSk, inAmounts, destinations, outAmounts, mixin):
    # inPk: vector of public keys corresponding to the owner inputs(sec format)
    # inSk: vector of private keys corresponding to the public keys (format 32bytes number)
    # inAmounts: vector of number corresponding to the amount coming from corresponding public key
    # destinations: vector of public keys (sec format)
    # outAmounts: vector of the different amounts going to the respective destinations public keys (int)
    # mixin: the number of pk to get involved in the rings (int)
    ## return: destinations: a vector of destinations public keys as received (sec format)
    ##         destinationsCommitment: a vector of commitment assigned to each destinations public keys (32 bytes numbers)
    ##         I: part of MLSAG, a vector of pk in sec format corresponding the the sha256 hash of the sender pk 
    ##         c_0: part of MLSAG, first sha3_256 (keccak) of the consecutive series of the MLSAG 
    ##         ss: part of MLSAG, a matrix of "random" 32 bytes number
    ##         infos: an array of ecdhEncode result containing the amount paid to the corresponding output pk
    ##         rangeSig: vector of rangeSig (format TODO)

    print("------ Let's create a the transaction -------")
    assert mixin < MAX_MIXIN and mixin > 0, "The number of ring participant should be between 0 and " + str(MAX_MIXIN) + "\n Aborting..."
    assert len(inSk) == len(inPk) and len(inAmounts) == len(inPk), \
        "The number of private key doesn't match the number of public key or the number of input amounts.\n\
        Aborting..."
    assert len(destinations) == len(outAmounts), \
        "The number of outputs addresses should match the number of outputs amounts.\n\
        Aborting..."
    m = len(inSk)
    for i in range(0, m):
        assert inAmounts[i] > 0 and inAmounts[i] < MAX_AMOUNT, \
            "The ingoing amount #" + str(i) + " should be between 0 and " + str(MAX_AMOUNT) + "\n\
            Aborting..."
    outNum = len(destinations)
    for i in range (0, outNum):
        assert outAmounts[i] > 0 and outAmounts[i] < MAX_AMOUNT, \
            "The outgoing amount #" + str(i) + " should be between 0 and " + str(MAX_AMOUNT) + "\n\
            Aborting..."

    for i in range(0, m):
        assert g.from_string(inSk[i], curve=crv).verifying_key.to_string() == inPk[i], \
            "One secret key doesn't match the corresponding public key.\n\
            Aborting..."

    print("------ All arguments are good, next ! -------")

    inSkMasks = [] 
    inPkMasks = [] 
    for i in range(0, m):
        skMask = to_32_bytes_number(random.randrange(crv.order))
        inSkMasks.append(skMask)
        pkMask = g.from_string(skMask, curve=crv).verifying_key
        aH = hash_to_point(to_32_bytes_number(1)).pubkey.point * inAmounts[i]
        pkMaskPoint = pkMask.pubkey.point + aH
        inPkMasks.append(VerifyingKey.from_public_point(pkMaskPoint).to_string())

    destinationsCommitment = []
    infos = []
    rangeSig = []
    outSkMasks = []
    for i in range(0, outNum):
        print("------Creating rangeproof for amount#" + str(i+1) + "-------")
        outCommit, outSkMask, rg = proveRange(outAmounts[i])
        destinationsCommitment.append(outCommit)
        outSkMasks.append(outSkMask)
        rangeSig.append(rg)
        hiddenMask, hiddenAmount, senderPk = ecdhEncode(outSkMask, to_32_bytes_number(outAmounts[i]), destinations[i])
        infos.append([hiddenMask, hiddenAmount, senderPk])

    print("------  Rangeproofs are valid. Next   -------")

    pkMatrix, pkMasksMatrix, index = populateFromBlockchain(inPk, inPkMasks, mixin)

    print("------Matrix populated, going further!-------")

    I, c_0, ss = prepareMG(pkMatrix, pkMasksMatrix, inSk, inSkMasks, destinationsCommitment, outSkMasks, index)

    print("------Transaction created with succes!-------")

    return pkMatrix, destinations, destinationsCommitment, I, c_0, ss, infos, rangeSig

def prepareMG(pubsK, pubsC, inSk, inSkMask, outC, outSkMasks, index):
    # pubsK: matrix of public key (size: qxm, sec format)
    # pubsC: matrix of commitment for pk (size: qxm, 32bytes)
    # inSk: vector of private key (size: m, bytes32 format)
    # inSkMask: vector of mask for the corresponding sk (size: m, 32bytes)
    # outC: vector of commitment for pk (hidden amount) (size: outPKsize, 32bytes)
    # outSkMasks: vector mask for out public keys (bytes32)
    # index: index of where in the pubsK matrix our pks are located
    ## returns: same a genMG

    print("------ Preparing the matrix for the MG-------")

    rowsQ = len(pubsK)
    if debug:
        assert len(pubsK) == len(pubsC) and len(pubsK) > 0, "\
            Mismatch in the number of public commitment and keys.\nAborting..."
    colsM = len(pubsK[0])
    if debug:
        assert len(inSk) == len(inSkMask) and len(inSk) == colsM, \
            "Mismatch in the number of private keys or private key masks.\nAborting..."
        for i in range(0, rowsQ): 
            assert len(pubsK[i]) == len(pubsC[i]) and len(pubsK[i]) == colsM, \
                "Mismatch in the number of public commitment and keys.\nAborting..."
        assert index >= 0 and index < rowsQ, "index: " + str(index) + " should be between 0 and "\
            + str(rowsQ) + " (the number of public key).\nAborting..."
        assert len(outC) == len(outSkMasks) and len(outC) > 0, \
            "Mismatch in the number of private commitment and keys.\nAborting..."

    matrix = [[None for x in range(colsM + 1)] for y in range(rowsQ)]
    sk = [None for x in range(colsM + 1)]
    for i in range(colsM):
        sk[i] = inSk[i]
        if i == 0:
            sk[colsM] = inSkMask[i]
        else:
            sk[colsM] = add_2_32b(sk[colsM], inSkMask[i])
        for j in range(rowsQ):
            matrix[j][i] = pubsK[j][i]
            if i == 0:
                matrix[j][colsM] = VerifyingKey.from_string(pubsC[j][i]).pubkey.point
            else:
                matrix[j][colsM] = matrix[j][colsM] + VerifyingKey.from_string(pubsC[j][i]).pubkey.point

    for i in range(len(outC)):
        sk[colsM] = sub_2_32b(sk[colsM], outSkMasks[i])
    for i in range(rowsQ):
        for j in range(len(outC)):
            point = VerifyingKey.from_string(outC[j]).pubkey.point
            matrix[i][colsM] = matrix[i][colsM] + VerifyingKey.from_public_point(Point(crv.curve, point.x(), (-point.y()) % crv.curve.p(), crv.order)).pubkey.point

    for j in range(rowsQ):
        matrix[j][colsM] = VerifyingKey.from_public_point(matrix[j][colsM]).to_string()

    print("------ Done with the matrix for the MG-------")

    #TODO message
    return genMG("", matrix, sk, index)

def list_to_bytes(list):
    ret = list[0]
    for x in range(1, len(list)):
        ret += list[x]
    return ret

def genMG(message, matrix, sk, index):

    n = len(matrix)
    if debug:
        assert n > 0, "No public key received.\nAborting..."
    m = len(matrix[0])
    if debug:
        assert m == len(sk), "The number of secret key doesn't match the number of public key.\nAborting..."
        for i in range(0, n):
            assert len(matrix[i]) == m, "Public key array is not rectangular.\nAborting..."
        assert m > 0, "No public key in the array.\nAborting..."
        assert index >= 0 and index < m, "Not a valid index.\nAborting..."
        for i in range(0, m):
            assert g.from_string(sk[i], curve=crv).verifying_key.to_string() == matrix[index][i], \
                "One secret key doesn't match the public key. Index: " + str(i) + "\n\
                Aborting..."

    message_bytes = bytes(message, 'UTF-8')

    alpha = [None for x in range(m)]
    I = [None for x in range(m)]
    ss = [[None for x in range(m)] for y in range(n)]
    
    L = [[None for x in range(m)] for y in range(n)] 
    R = [[None for x in range(m)] for y in range(n)] 

    for j in range(0, m):
        skJHashPub_point = hash_to_point(matrix[index][j]).pubkey.point * to_int_from_bytes(sk[j])
        I[j] = VerifyingKey.from_public_point(skJHashPub_point, curve=crv).to_string()
 
        alpha[j] = to_32_bytes_number(random.randrange(crv.order))
        L[index][j] = g.from_string(alpha[j], curve=crv).verifying_key.to_string()

        alphaHashPub_point = hash_to_point(matrix[index][j]).pubkey.point * to_int_from_bytes(alpha[j])
        R[index][j] = VerifyingKey.from_public_point(alphaHashPub_point, curve=crv).to_string()

    c_idx_1 = sha3.keccak_256(message_bytes + list_to_bytes(L[index]) + list_to_bytes(R[index])).digest()



    c = c_idx_1
    c_0 = None
    for i in range(1, n): 
        idx = (index + i) % n
        for j in range(0, m):
            # assert ss[idx][j] == None, "Hmm sounds bad"
            ss[idx][j] = to_32_bytes_number(random.randrange(crv.order))

            c_PubK = VerifyingKey.from_string(matrix[idx][j], curve=crv).pubkey.point * to_int_from_bytes(c)
            sj_G = g.from_string(ss[idx][j], curve=crv)
            L_point = c_PubK + sj_G.verifying_key.pubkey.point
            L[idx][j] = VerifyingKey.from_public_point(L_point, curve=crv).to_string()


            c_I = VerifyingKey.from_string(I[j], curve=crv).pubkey.point * to_int_from_bytes(c)
            R_point = hash_to_point(matrix[idx][j]).pubkey.point * to_int_from_bytes(ss[idx][j]) + c_I
            R[idx][j] = VerifyingKey.from_public_point(R_point, curve=crv).to_string()

        c = sha3.keccak_256(message_bytes + list_to_bytes(L[idx]) + list_to_bytes(R[idx])).digest();
        if idx == n-1:
            c_0 = c

    print("------ Done with generating the MLSAG -------")

    if debug:
        # sanity check:
        L_tmp = [None for x in range(m)]
        R_tmp = [None for x in range(m)]

        for j in range(0, m):
            ss[index][j] = to_32_bytes_number((to_int_from_bytes(alpha[j]) - to_int_from_bytes(c) * to_int_from_bytes(sk[j])) % crv.order)

            c_PubK = VerifyingKey.from_string(matrix[index][j], curve=crv).pubkey.point * to_int_from_bytes(c)
            sj_G = g.from_string(ss[index][j], curve=crv)
            L_point = c_PubK + sj_G.verifying_key.pubkey.point
            L_tmp[j] = VerifyingKey.from_public_point(L_point, curve=crv).to_string()

            c_I = VerifyingKey.from_string(I[j], curve=crv).pubkey.point * to_int_from_bytes(c)
            R_point = hash_to_point(matrix[index][j]).pubkey.point * to_int_from_bytes(ss[index][j]) + c_I
            R_tmp[j] = VerifyingKey.from_public_point(R_point, curve=crv).to_string()

        c_tmp = sha3.keccak_256(message_bytes + list_to_bytes(L_tmp) + list_to_bytes(R_tmp)).digest()
        assert L_tmp == L[index] and R_tmp == R[index], "Sanity check for computing ss[index] failed.\nAborting..."

    if debug:
        assert verifyMG(message, matrix, I, c_0, ss), "Ring verification failed.\nAborting..."
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

    L = [[None for x in range(m)] for y in range(n)] 
    R = [[None for x in range(m)] for y in range(n)] 

    c = c_0
    for idx in range(0, n): 
        for j in range(0, m):
            c_PubK = VerifyingKey.from_string(matrix[idx][j], curve=crv).pubkey.point * to_int_from_bytes(c)
            sj_G = g.from_string(ss[idx][j], curve=crv)
            L_point = c_PubK + sj_G.verifying_key.pubkey.point
            L[idx][j] = VerifyingKey.from_public_point(L_point, curve=crv).to_string()

            c_I = VerifyingKey.from_string(I[j], curve=crv).pubkey.point * to_int_from_bytes(c)
            R_point = hash_to_point(matrix[idx][j]).pubkey.point * to_int_from_bytes(ss[idx][j]) + c_I
            R[idx][j] = VerifyingKey.from_public_point(R_point, curve=crv).to_string()

        c = sha3.keccak_256(message_bytes + list_to_bytes(L[idx]) + list_to_bytes(R[idx])).digest();

    return c == c_0

def populateFromBlockchain(publicKey, inPkMasks, mixin):
    # publicKey: vector of pk, sec format
    # inPkMasks: vector of bytes32 (format from verifyingkey.to_string())
    # mixin: number of other pk involved, int
    ## return: pk matrix (format sec), 
    ##         coressponding masks matrix, 
    ##         index of our pks in the matrix

    if debug:
        assert len(publicKey) == len(inPkMasks), \
            "Mismatch in the number of public key and their corresponding mask\n\
            Aborting..."
    m = len(publicKey)
    index = random.randrange(mixin - 1)
    pkMatrix = []
    maskMatrix = []
    for i in range(0, mixin):
        if i != index:
            pkMatrix.append([getKeyFromBlockchain() for i in range(0, m)])
            maskMatrix.append([hash_to_point(to_32_bytes_number(random.randrange(crv.order))).to_string() for i in range(0, m)])
        else: 
            pkMatrix.append(publicKey)
            maskMatrix.append(inPkMasks)
    return pkMatrix, maskMatrix, index

def getKeyFromBlockchain():
    #TODO
    ## return: a public key "from the blockchain" in the to_string format
    x = to_32_bytes_number(random.randrange(crv.order))
    return g.from_string(x).verifying_key.to_string()

def GenSchnorrNonLinkable(x, P1, P2, index):
    # x: bytes32
    # P1: bytes32
    # P2: bytes32

    if index == 0:
        a = to_32_bytes_number(random.randrange(crv.order))
        L1 = g.from_string(a).verifying_key.to_string()
        s2 = to_32_bytes_number(random.randrange(crv.order))
        c2 = hashlib.sha256(L1).digest()
        L2 = VerifyingKey.from_public_point(g.from_string(s2).verifying_key.pubkey.point + (VerifyingKey.from_string(P2).pubkey.point * to_int_from_bytes(c2))).to_string()
        c1 = hashlib.sha256(L2).digest()
        s1 = to_32_bytes_number((to_int_from_bytes(a) -  to_int_from_bytes(x) * to_int_from_bytes(c1)) % crv.order)

        # sanity check
        if(debug):
            L1p = VerifyingKey.from_public_point(g.from_string(s1).verifying_key.pubkey.point + (VerifyingKey.from_string(P1).pubkey.point * to_int_from_bytes(c1))).to_string()
            assert L1p == L1, "Sanity check failed in GenSchnorr 1\nAborting..."
    if index == 1:
        a = to_32_bytes_number(random.randrange(crv.order))
        L2 = g.from_string(a).verifying_key.to_string()
        s1 = to_32_bytes_number(random.randrange(crv.order))
        c1 = hashlib.sha256(L2).digest()
        L1 = VerifyingKey.from_public_point(g.from_string(s1).verifying_key.pubkey.point + (VerifyingKey.from_string(P1).pubkey.point * to_int_from_bytes(c1))).to_string()
        c2 = hashlib.sha256(L1).digest()
        s2 = to_32_bytes_number((to_int_from_bytes(a) - (to_int_from_bytes(x) * to_int_from_bytes(c2))) % crv.order)
        # sanity check
        if(debug):
            L2p = VerifyingKey.from_public_point(g.from_string(s2).verifying_key.pubkey.point + (VerifyingKey.from_string(P2).pubkey.point * to_int_from_bytes(c2))).to_string()
            assert L2p == L2, "Sanity check failed in GenSchnorr 2\nAborting..."
    return L1, s1, s2

def VerSchnorrNonLinkable(P1, P2, L1, s1, s2):
    # P1: Pubkey in from_string format (32 bytes)
    # P2: Pubkey in from_string format (32 bytes)
    # L1: output of GenSchnorr, pubkey in from_string format (32 bytes)
    # s1: output of GenSchnorr, number (32 bytes)
    # s2: output of GenSchnorr, number (32 bytes)
    c2 = hashlib.sha256(L1).digest()
    L2 = VerifyingKey.from_public_point(g.from_string(s2).verifying_key.pubkey.point + (VerifyingKey.from_string(P2).pubkey.point * to_int_from_bytes(c2))).to_string()
    c1 = hashlib.sha256(L2).digest()
    L1p = VerifyingKey.from_public_point(g.from_string(s1).verifying_key.pubkey.point + (VerifyingKey.from_string(P1).pubkey.point * to_int_from_bytes(c1))).to_string()
    assert L1 == L1p, "GenSchnorrNonLinkable failed to generate a valid signature.\nAborting..."

def GenASNL(x, P1, P2, indices):
    # x: vector of 32bytes number serving as mask
    # P1: Public key 1, from_string format (32bytes)
    # P2: Public key 2, from_string format (32bytes)
    # indices: vector of number (1 and 0 in our case) to specify which public key will be used to close the ring
    ## returns: L1: vector of public key (to_string format, 32bytes)
    ##          s2: vector of 32 bytes number
    ##          s: 32 bytes number, aggregate of s1
    n = len(x)
    L1 = [None] * n
    s1 = [None] * n
    s2 = [None] * n
    s = to_32_bytes_number(0)
    print("Generating the per bit signature of the amount")
    for j in range(0, n):
        if j % (n//10) == 0:
            print("[", end='')
            for u in range(0, 10):
                if u < (j*10)/n:
                    print("#", end='')
                else:
                    print(" ", end='')
            print("]")
        L1[j], s1[j], s2[j] = GenSchnorrNonLinkable(x[j], P1[j], P2[j], indices[j])
        if debug:
            VerSchnorrNonLinkable(P1[j], P2[j], L1[j], s1[j], s2[j])
        s = add_2_32b(s, s1[j])
    return L1, s2, s

def VerASNL(P1, P2, L1, s2, s):
    # P1: Public key 1, from_string format (32bytes)
    # P2: Public key 2, from_string format (32bytes)
    # L1: vector of public key (to_string format, 32bytes)
    # s2: vector of 32 bytes number
    # s: 32 bytes number, aggregate of s1
    n = len(P1)
    LHS = to_32_bytes_number(0)
    RHS = g.from_string(s).verifying_key.pubkey.point
    for j in range(0, n):
        c2 = hashlib.sha256(L1[j]).digest()
        L2Point = g.from_string(s2[j]).verifying_key.pubkey.point + (VerifyingKey.from_string(P2[j]).pubkey.point * to_int_from_bytes(c2))
        L2 = VerifyingKey.from_public_point(L2Point).to_string()
        if j == 0:
            LHS = VerifyingKey.from_string(L1[j]).pubkey.point
        else:
            LHS = LHS + VerifyingKey.from_string(L1[j]).pubkey.point
        c1 = hashlib.sha256(L2).digest()
        RHS = RHS + (VerifyingKey.from_string(P1[j]).pubkey.point * to_int_from_bytes(c1))
    assert VerifyingKey.from_public_point(LHS).to_string() == VerifyingKey.from_public_point(RHS).to_string(), \
        "GenASNL failed to generate a valid signature.\nAborting..."

def proveRange(amount):
    # amount: the amount to prove range from, in int
    ## returns: C_pk: output commitment serving as a public key (to_string 32bytes format)
    ##          mask: part of the private key for C_pk. mask * G + amount * H == C_pk, 32 bytes number format
    ##          rg: vector of range proofs, each entry contain a vector of public key Ci and a aggregate signature.
    ##              The aggregate signature itself contains L1: vector of public key (to_string format, 32bytes)
    ##                                                      s2: vector of 32 bytes number
    ##                                                      s: 32 bytes number, aggregate of s1
    ##              For more infos on asig, see GenASNL(...)

    HPow2 = hash_to_point(to_32_bytes_number(1)).pubkey.point
    H2 = []
    for i in range(0, ATOMS):
        H2.append(VerifyingKey.from_public_point(HPow2).to_string())
        HPow2 = HPow2 * 2

    def d2b(n, digits):
        b = [0] * digits
        i = 0
        while n:
            b[i] = n & 1
            i = i + 1
            n >>= 1
        return b 

    bb = d2b(amount, ATOMS) #gives binary form of bb in "digits" binary digits
    mask = to_32_bytes_number(0)
    
    C = to_32_bytes_number(0)
    ai = []
    Ci = []
    CiH = []

    print("------  Preparing different elements  -------")
    for i in range(0, ATOMS):
        ai.append(to_32_bytes_number(random.randrange(crv.order)))
        mask = add_2_32b(mask, ai[i]) #creating the total mask since you have to pass this to receiver...
        if bb[i] == 0:
            Ci.append(g.from_string(ai[i]).verifying_key.to_string())
        if bb[i] == 1:
            Ci.append(VerifyingKey.from_public_point(\
                g.from_string(ai[i]).verifying_key.pubkey.point + \
                VerifyingKey.from_string(H2[i]).pubkey.point\
                ).to_string())


        negateH2 = Point(crv.curve, VerifyingKey.from_string(H2[i]).pubkey.point.x(), (-VerifyingKey.from_string(H2[i]).pubkey.point.y()) , crv.order)
        CiH.append(VerifyingKey.from_public_point(VerifyingKey.from_string(Ci[i]).pubkey.point + negateH2).to_string()) # ach scahde, pubkey - smth, how to do ?
        
        if debug and bb[i] == 1:
            #Sanity check A + h2 - h2 == A
            assert g.from_string(ai[i]).verifying_key.to_string() == CiH[i], \
                "Sanity check failed in proveRange !" + bytes.hex(g.from_string(ai[i]).verifying_key.to_string()) +\
                " ---- " + bytes.hex(CiH[i])

    L1, s2, s = GenASNL(ai, Ci, CiH, bb)
    if debug:
        VerASNL(Ci, CiH, L1, s2, s)


    asig = [L1, s2, s]
    rg = [Ci, asig]

    C_point = VerifyingKey.from_string(Ci[0]).pubkey.point
    for i in range(1, len(Ci)):
        C_point = C_point + VerifyingKey.from_string(Ci[i]).pubkey.point

    C = to_32_bytes_number(0)
    for i in range(0, len(Ci)):
        C = add_2_32b(C, Ci[i])


    C_pk = VerifyingKey.from_public_point(C_point)
    if debug:
        x = hash_to_point(to_32_bytes_number(1)).pubkey.point * amount + g.from_string(mask).verifying_key.pubkey.point
        assert C_pk.to_string() == VerifyingKey.from_public_point(x).to_string(), \
            "Something went wrong in the genreation of the commitment! " +\
            bytes.hex(C_pk.to_string()) + " should equal " + bytes.hex(VerifyingKey.from_public_point(x).to_string())

    return C_pk.to_string(), mask, rg


def test():
    print("------  Entering the first test case. -------")

    for i in range(0, 10):
        x = random.randrange(2**256)
        assert x == to_int_from_bytes(to_32_bytes_number(x)), "bytes <-> int conversion failed, x = %d" % (x)
    
    print("------ Entering the second test case. -------")

    for i in range(0, 10):
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


with open("contractAddress.txt") as f:
    content = f.readlines()
# you may also want to remove whitespace characters like `\n` at the end of each line
content = [x.strip() for x in content]
found = False
i = 0
while not found and i < len(content):
    if content[i][0:7] == 'RingCT:':
        found = True
        contractAddress = content[i][8:50]
    i += 1
if not found:
    import sys
    sys.exit("Error message")




inAmounts = [3,4]
inSk = []
inPk = []
for i in range(0, len(inAmounts)):
    sk = to_32_bytes_number(random.randrange(crv.order))
    inSk.append(sk)
    inPk.append(g.from_string(sk, curve=crv).verifying_key.to_string())

outAmount = [1, 6]

outputPub = [VerifyingKey.from_sec(bytes.fromhex(pub)).to_string(), VerifyingKey.from_sec(bytes.fromhex(pub5)).to_string()]
matrix, destinations, destinationsCommitment, I, c_0, ss, infos, rangeSig =  createTransaction(inPk, inSk, inAmounts, outputPub, outAmount, 2)


# # matrix=[[VerifyingKey.from_sec(bytes.fromhex(pub2)).to_string(), VerifyingKey.from_sec(bytes.fromhex(pub3)).to_string()], \
# #         [VerifyingKey.from_sec(bytes.fromhex(pub)).to_string(), VerifyingKey.from_sec(bytes.fromhex(pub4)).to_string()],\
# #         [VerifyingKey.from_sec(bytes.fromhex(pub3)).to_string(), VerifyingKey.from_sec(bytes.fromhex(pub5)).to_string()]]
# # I, c_0, ss = genMG(message="hello2", matrix=matrix, \
# #     sk=[bytes.fromhex(pri), bytes.fromhex(pri4)], index=1)
print("-----I-----")
print(I)
print("-----c-----")
print(c_0)
print("-----ss-----")
print(ss)
print("-----matrx-----")
print(matrix)
# I = [b'\xe6\xcf\x13t\x10\xd9T5RJD\xca\x8c+\xf1~(\x9c\x19\x00<\xd6(\xc3\x06#\x9e\xb8\x13D\x00\\\xdf\x8e\x8cUM\xc8\xda\x80HEd\x1d8\xf1\x8b\xdf\x05\xec\x12\xa8\xfc\xfd\xde\x84N\x0b\x0c\xdeh\x15O\xe5', b'}\x94\xf1>\xd3\xe9\xcbvw\x954@\xec\x07\xd3\xbb\xb9\x8e\xd5\xf2X\x80\xa9f=i\xb7\xa2\x12T\xa7\x9d\xa31$F\xad\x02\xe1B\xe8\xfb~\xde\xd6\x1a n\x1b\xc1\xa2f\xdfO\xd7\xd8wrr\xd14O\xa5\xf4', b"\x9b9\xec6\x03\x07\x11S\xb71W\\g\xa2\x93Gy\x99\x89\xc2$f\x08\xc4i\x8a\xcd\xc87\x0bQf\xfb\xb7\xba\xd99x\x80\x98\xed\x9e\x80\xceF\x82E\x0c*%\x90S\xe5\xde\x90\xe4'U\xa7\xa1\x8fVK\xc1"]
# c_0 = b'x\xd5\x08)P \xe2\x91\xb9\x96f\x0e\xb56\x9aN\x834\x9ds|\xfa\x87E\xdb\x1f\x1e8\xcal\xad\xaf'
# ss= [[b"\x1c\xdfl\xee\x11\x04\xbaz\xedz\x06\xdf\xa6\xe4Q\x830\x1e\xdb'\xd2|\xc7m\x8d\xa9?i$NI\xf6", b'\xe3\xdc\xcd\xf7\x89\x08\xdd\xf7{\xf4|\xc9G\xa7+1\xb1f\x00\xc2\xf7\xfbsnt\xa2\r\xa0o\xec\xc0\\', b"\x18\x97\xe30\x87\x1c\xfa\xd7\x7f\xfb\xb2\xe5\xd0\xe1\x08dx\x16/t\xbb@\xd8'l\xe5\x01\xc8\x1f\x0c\x0bm"], [b"\xaa\xedz'\x19CV\xf8\x859\xd2\x17\x12\x9cW\xa2b\xad\xaa\x98\x0c\x1bt\xad@.H\xa6D\x8dW(", b"\x96\x82%\x86?:,\xcb=\x8f\xc0\x96Aw\xaf\xd9\xf5\xdfl\xfe2\xa1#R\xa9'=\xd0G\x15U\x18", b'\xf3\x87u\xc8^`/\x01e\xf17\x91\xde\xc2]\xc2\xbaB\xd1B\x80\xf3s\xfdUj\xd22\x99\xa2\xb9;']]
# matrix = [[b'BZ\xa4\xcdW\xbc\xa8\xa9P+\xb8\xdb\x1c\x0c\xc7\xbc\x8f\xf3\xf00\x92\xe4\xb0(\x9c\x81>\xb4V+\xf6\xc2\xa1hWAB4\xbe\xde\x1d\xed\xc1\x00\xb6\xf8\xd2\x92\xc4_C\xc1\xc5[\x18\x91\x08\xad\x10\x8e\xe5\xfe\x0cE', b'\x9c\x8cj6\xf6\x96\xc8B\x05\xd6\x13Q\xbd\x8d\xd7\xbeS\xd4\x9c\xb0\xcb\x8a\xa5\xa1M\x9c\xf7us\x0byd\x8b\xa5w\xb5\x99\xd9J\x9b\x8f\x97M\x05\xec\xa5\x15V\x9au\xfa\x13\xdb\xc3[\xeb4*\xc2\xa3y\xb4\x9eg'], [b'\x17\xf6\xb64\xdf\x19\xa0 8\xf7\x9d\x0c\x05Z\xa1\xdf\xab\x1d@\xdf\xdd\xd5\xccd\xdd\n\xdejQ\xcdm\xf8\x1b]\xf8\xd0\xceY\t&$\xf0\xd7\xd9\xd4E\xf8\xf0v\xc3Y\xa0\x0f\xe8\xf5\xa3|\xc3K\x0c=\xebY4', b'Y\xc4:\xd7\x88\x96\xde\x8b\xfa\xf1\x9dy(\xfc\xf2\xf3p"\x95\xe0\x1b\xeb\xdd\xdan\x07\x93)\x15eP&\xa9\xb7r \xf9\xd0F\x85I\xd6\xb0\x82\n\x8e\xc4\xf0\x87\x82\xac\xe6#\xf6\x1e\xd6\xf2K\xdc\x1e\xce\x17\xf3y']]
send_ring("", matrix, c_0, ss, I)

# test()