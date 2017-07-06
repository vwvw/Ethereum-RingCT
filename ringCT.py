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
rangSigBool = False
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

def hash_to_point_special(pubK):
    p = VerifyingKey.from_string(pubK).pubkey.point
    return hash_to_point(to_32_bytes_number(p.x())+ to_32_bytes_number(p.y()))

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
    filterNames = ['Log Error', 'Print string', 'Print bool', 'Print address', 'Print uint256', 'PrintStringAndUint(string,uint256)']
    to_keccack = ["LogErrorString(string)", "PrintString(string)", "PrintBool(bool)", "PrintAddress(address)", "PrintUint(uint256)", "PrintStringAndUint(string,uint256)"]
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



    cb = connection.eth_coinbase()
    results = connection.call_with_transaction(cb, contractAddress, 
        'y()',[])
        # 'testb(string,uint256,uint256,bytes32[2][],bytes32,uint256,uint256,bytes32[],uint256,bytes32[2][])',\
        # [message,\
        # len(pubkey), len(pubkey[0]), pubkeysAlligned,\
        # c0,\
        # len(ss), len(ss[0]), ssAlligned,\
        # len(II), IIAlligned], gas=99999999999, gas_price=1)
    bashCommand = 'curl -X POST 127.0.0.1:8545 -m 3 --data ' + results.replace(" ", "")
    import subprocess
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    print(output)
    print("ERROR: ",error)
    print("------Transaction sent, waiting events-------")
    for i in range(0, 2):
        time.sleep(1);
        if i%10== 0:
            print(i)

    for i in range(0, len(filter)):
        change = connection.eth_getFilterChanges(filter[i])
        if len(change) > 0:
            for j in range(0, len(change)):
                if filterNames[i] == "Print uint256":
                    print(filterNames[i] + " result " + str(j) + ":\n" + str(to_int_from_bytes(bytes.fromhex(change[j]["data"][2:]))))
                else:
                    print(filterNames[i] + " result " + str(j) + ":\n" + str(bytes.fromhex(change[j]["data"][2:])))

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

    if debug:
        (newMatrix, (L, R, I, c_0, ss)) = prepareMG(pkMatrix, pkMasksMatrix, inSk, inSkMasks, destinationsCommitment, outSkMasks, index)
        print("------Transaction created with succes!-------")
        return newMatrix, L, R, destinations, destinationsCommitment, I, c_0, ss, infos, rangeSig
    else:
        (newMatrix, (I, c_0, ss)) = prepareMG(pkMatrix, pkMasksMatrix, inSk, inSkMasks, destinationsCommitment, outSkMasks, index)
        print("------Transaction created with succes!-------")
        return newMatrix, destinations, destinationsCommitment, I, c_0, ss, infos, rangeSig

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
    return (matrix, genMG("", matrix, sk, index))

def list_to_bytes(list):
    # [[None, None] for x in range(m)]
    ret = to_32_bytes_number(list[0][0]) + to_32_bytes_number(list[0][1])
    for x in range(1, len(list)):
        ret += to_32_bytes_number(list[x][0]) + to_32_bytes_number(list[x][1])
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
    
    L = [[[None, None] for x in range(m)] for y in range(n)] 
    R = [[[None, None] for x in range(m)] for y in range(n)] 

    for j in range(0, m):
        skJHashPub_point = hash_to_point(matrix[index][j]).pubkey.point * to_int_from_bytes(sk[j])
        I[j] = VerifyingKey.from_public_point(skJHashPub_point, curve=crv).to_string()
 
        alpha[j] = to_32_bytes_number(random.randrange(crv.order))
        LPoint = g.from_string(alpha[j], curve=crv).verifying_key.pubkey.point
        L[index][j] = [LPoint.x(), LPoint.y()]

        alphaHashPub_point = hash_to_point_special(matrix[index][j]).pubkey.point * to_int_from_bytes(alpha[j])
        R[index][j] = [alphaHashPub_point.x(), alphaHashPub_point.y()]

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
            L[idx][j] = [L_point.x(), L_point.y()]


            c_I = VerifyingKey.from_string(I[j], curve=crv).pubkey.point * to_int_from_bytes(c)
            R_point = hash_to_point_special(matrix[idx][j]).pubkey.point * to_int_from_bytes(ss[idx][j]) + c_I
            R[idx][j] = [R_point.x(), R_point.y()]

        c = sha3.keccak_256(message_bytes + list_to_bytes(L[idx]) + list_to_bytes(R[idx])).digest();
        if idx == n-1:
            c_0 = c

    print("------ Done with generating the MLSAG -------")

    if debug:
        # sanity check:
        L_tmp = [[None, None] for x in range(m)]
        R_tmp = [[None, None] for x in range(m)]

        for j in range(0, m):
            ss[index][j] = to_32_bytes_number((to_int_from_bytes(alpha[j]) - to_int_from_bytes(c) * to_int_from_bytes(sk[j])) % crv.order)

            c_PubK = VerifyingKey.from_string(matrix[index][j], curve=crv).pubkey.point * to_int_from_bytes(c)
            sj_G = g.from_string(ss[index][j], curve=crv)
            L_point = c_PubK + sj_G.verifying_key.pubkey.point
            L_tmp[j] = [L_point.x(), L_point.y()]

            c_I = VerifyingKey.from_string(I[j], curve=crv).pubkey.point * to_int_from_bytes(c)
            R_point = hash_to_point_special(matrix[index][j]).pubkey.point * to_int_from_bytes(ss[index][j]) + c_I
            R_tmp[j] = [R_point.x(), R_point.y()]

        c_tmp = sha3.keccak_256(message_bytes + list_to_bytes(L_tmp) + list_to_bytes(R_tmp)).digest()
        assert L_tmp == L[index] and R_tmp == R[index], "Sanity check for computing ss[index] failed.\nAborting..."

    if debug:
        assert verifyMG(message, matrix, I, c_0, ss), "Ring verification failed.\nAborting..."
        print("--------- Done with verifying the MLSAG  -------")
        return L, R, I, c_0, ss
    else:
        return I, c_0, ss

def verifyMG(message, matrix, I, c_0, ss):
    n = len(ss)
    assert n > 0, "No ss in the ring signature. Length = 0."
    assert len(matrix) == n, "Mismatch"
    m = len(ss[0])
    for i in range(0, n):
        assert len(ss[i]) == m, "Non rectangular ss in the ring signature."
    assert m > 0, "No ss in the ring siganture. Length ss[0] = 0"
    assert len(I) == len(ss[0]), "Not the same number of pubkey hash (I) as of secret (ss)."

    message_bytes = bytes(message, 'UTF-8')

    L = [[[None, None] for x in range(m)] for y in range(n)] 
    R = [[[None, None] for x in range(m)] for y in range(n)] 

    c = c_0
    for idx in range(0, n): 
        for j in range(0, m):
            print("----- " + str(idx * m + j) + "")
            c_PubK = VerifyingKey.from_string(matrix[idx][j], curve=crv).pubkey.point * to_int_from_bytes(c)
            sj_G = g.from_string(ss[idx][j], curve=crv)
            L_point = c_PubK + sj_G.verifying_key.pubkey.point
            L[idx][j] = [L_point.x(), L_point.y()]
            print(sj_G.verifying_key.pubkey.point.x())
            print(sj_G.verifying_key.pubkey.point.y())
            print("^^^^^^^")
            print(c_PubK.x())
            print(c_PubK.y())
            print("++++++")
            
            c_I = VerifyingKey.from_string(I[j], curve=crv).pubkey.point * to_int_from_bytes(c)
            p = hash_to_point_special(matrix[idx][j]).pubkey.point * to_int_from_bytes(ss[idx][j])
            # opo = VerifyingKey.from_string(matrix[idx][j]).pubkey.point
            # print(opo.x())
            # print(opo.y())
            # opo2 = hashlib.sha256(to_32_bytes_number(opo.x())+to_32_bytes_number(opo.y())).digest()
            # print(int.from_bytes(opo2, 'big'))
            # print(g.from_string(opo2).verifying_key.pubkey.point.x())
            # print(g.from_string(opo2).verifying_key.pubkey.point.y())
            # print("^^^^^^^")
            # print(g.from_secret_exponent(int.from_bytes(opo2, 'big')).verifying_key.pubkey.point.x())
            # print(g.from_secret_exponent(int.from_bytes(opo2, 'big')).verifying_key.pubkey.point.y())
            # print("++++++")
            print(str(p.x()))
            print(str(p.y()))
            print("......")
            print(str(c_I.x()))
            print(str(c_I.y()))
            print("******")
            R_point = p + c_I
            R[idx][j] = [R_point.x(), R_point.y()]

        print(L[idx])
        print(R[idx])

        c = sha3.keccak_256(message_bytes + list_to_bytes(L[idx]) + list_to_bytes(R[idx])).digest();
        print("CCCCCCCC = ", end="")
        print(str(int.from_bytes(c, 'big')))

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
    if rangSigBool == True:
        L1, s2, s = GenASNL(ai, Ci, CiH, bb)
        if debug:
            VerASNL(Ci, CiH, L1, s2, s)

        asig = [L1, s2, s]
        rg = [Ci, asig]
    else:
        rg = 1

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
upu = 0
pri = "07ca500a843616b48db3618aea3e9e1174dede9b4e94b95b2170182f632ad47c"
pri4 = "79d3372ffd4278affd69313355d38c6d90d489e4ab0bbbef9589d7cc9559ab6d"
pri5 = "00dff8928e99bda9bb83a377e09c8bf5d110c414fa65d771b7b84797709c7dd0b1"
pub = "0462abcca39e6dbe30ade7be2949239311162792bdb257f408ccd9eab65e18bc5bbcf8a3f08675bd792251a23d09a48a870644ba3923996cc5b5ec2d68043f3df3"
pub2 = "040ccad48919d8f6a206a1ac7113c22db62aa744a0700762b70aa0284d474c00203029637ce8e84f6551fd92a0db8e1f964ff13aa992e4cbfd1fb8fa33c6e6c53c"
pub3 = "049f742f925b554e2dc02e2da5cb9663ef810e9eefb30818b3c12bc26afb8dd7ba3461c0f7d2b997bf455973af308a71ed34ae415cfc946de84db3961db522e5d2"
pub4 = "04ef36c6d140e7970cc54c08e0e5d3173059ee6276dd0de99e09d10c49bd49e63c44e0a2e7180fff5e3e8a549027b8a37bc3a9437374ef1b7a05040b244a7bccc5"
pub5 = "04da11a42320ae495014dd9c1c51d43d6c55ca51b7fe9ae3e1258e927e97f48be4e7a4474c067154fdaa1c5b26dee555c3e649337605510cf9e1d5c1e657352e9c"
# createTransaction(bytes.fromhex(pri), bytes.fromhex(pub), [bytes.fromhex(pub2), bytes.fromhex(pub3)], [1, 2], 2)





# helloashjdagjdlas = []
# inAmounts = [3,4]
# inSk = []
# inPk = []
# for i in range(0, len(inAmounts)):
#     sk = to_32_bytes_number(random.randrange(crv.order))
#     inSk.append(sk)
#     inPk.append(g.from_string(sk, curve=crv).verifying_key.to_string())

# outAmount = [1, 6]

# outputPub = [VerifyingKey.from_sec(bytes.fromhex(pub)).to_string(), VerifyingKey.from_sec(bytes.fromhex(pub5)).to_string()]
# matrix, L, R, destinations, destinationsCommitment, I, c, ss, infos, rangeSig =  createTransaction(inPk, inSk, inAmounts, outputPub, outAmount, 2)
# upu = 1;

# print("I = ", end='')
# print(I)
# print("c = ", end='')
# print(c)
# print("ss = ", end='')
# print(ss)
# print("matrix = ", end='')
# print(matrix)
# print("L = ", end='')
# print(L)
# print("R = ", end='')
# print(R)

if(upu == 0):
    print("hllo")
    I = [b'\x91\x8e\xc1zmI\xf3\xe1\xeb\x96\x85\xea?\xd3w\x80\x86\xb8\xe2\xd9\x07\xfe\xe1\xa3\xb2\xfd\xfb\xd8\x0e\x91\x18\xfaxJ\x04\x079\xfc!\xa9\xa3\xd5\r#\xf6\xbf\x11\xbd\xc3\xe6\xdd\xc5:\x1b\xce+\xed\xa18\x9c\xec\xdf\x8a\xaf', b'Zj\n!U\xcd\x9b:\x82\xda\r\xd9+O\xe4AX\xcff\x8d%\xe6/4fd\xc547\\\xc8)\x02\xb9|\xb8\x81t\x1c\xc3;\xcbF\xb9\xda\xa6\x19\x8e\xcbo/\xf3`\xc8\xe8\xccBPv~\xc9\xc6at', b'Jj\x8f\xc2\xb3\x8c\x13+\x1b\x15\xfeu\x0f\xbcj\x90&|\x12\x82\x08f\xc6&\xe7\xb2\x98B`\xa7\xd4z,\x91\xf2KqG\x02\xbf\xf6\x02\xab\xadE\xc9\xb7zq\xc7\xac\xeeD\xae-\xdd\x17A\x15\x8aj\xba\x1d\xe7']
    c = b'\x8cF\x9e\x18\xe6\xc1\xc3\x10q,\x87Xy~\x11\t\xc0?\x9c\x95\xba\th\xa3\n\xb1E\xfd-xU\xee'
    ss = [[b'\xfe{H\xaa\x1aSA$\x96F\x8b\xc6\xf2\xe5x\x98\xfbO!\xca\xa3\xb5v\x0e\x9d\xc1 \xce\xb4Y&+', b'\t\xee\xc3>!\xeaNO*Fh\xa9\xa3|\x88\x91r\tBV+\x80\x1a\x82\xae\xbdJ\xbb\xca7\x9f\x03', b"\xecZQ\x94'\xe2\r.\xe4\x84\xf5\xb7)\x8b\x87\x02\xd4(\xcd\x13\x84\x0e,%\x06(\x92\xeb\x0e\x84\xe3\xf3"], [b'\x02\x95\xe3\x811\xe8\xfbwre\x9a\xed\xe6\xf9\xc6\xd9\xf1*\x9dfsW\x84gH\r\xa4c\xdf\xdcm\xcf', b'\xaa\xc6\xb2\x81\x86\x00>\x08\x8c\xcd\xdd\xf4\x07]4\x06G\xefx\xf3RyA\xce\x8f\xe1k=t\x95V\xb5', b'\xcbN]\xbc\xc9aO\x1a\xaa\xdcpJ\x1a\xf1\x18h\xc7\x92L\xd6\xc7\xb0N\xc4A\xb3l%%\x96\xc8w']]
    matrix = [[b'\x83\x8e\xea\xa8.\x8a\xcd\x95-\x82g\x95\xb4\xfdGQ\x13|Z\xbaHe\xb8>v\x03\ruK6xp\xad\xb9T\xb5\x8f$\xc8m\x16\\\x926\xd8\x81\x967?"\xc6\x95\xd1\xf94\xd6\xdd\xd6\xde\xb9QV_\xd2', b'\xa5\x84KFO\xd8V\x94\x92g:\xae!L\x07\xd8?\xf7\x0b\xe5\xed\xd0\x99\xe4\x9a\xa9\x94\x1e\xc4e\xe2t\x16r\xb1\xb4g\x0f\xbb\x13\x12\x0e\x99\xb6,\xadch\xfc\xe7o\x83 \x9d\x92\xbd\xfb\xa4m\xa9Ll\xce\x97', b'"~\\2\xbea|B/\xbc\xf7|\x99(\xfc\x90\xbe\xc1\x15\xd4\xe1\xc5\x7f\xc0E\x91\xae\xbe<4\xf4\xd0\nc\xff\x11{\xbfo\x81\xb1\x15F\xe0"\x19\'\xd3\x16{M\xb7\x1f\x01a\xb9VKZ\xdc\xc8\x00(\xfd'], [b'\xc3l\x1d\xd8\xa6"\xe2i.m\xaf\xd6\xb2\x1d?l\xca\x95\xe8\\:%\xd6\x1c\xfb\xb4\xb1\x8e\xc6\xb8i/\xcc&7\x06\x81\xf6e[\xb23\x93\xc1\x98\xec\x94\x1e.Ac\xb4\x13\xf2\xeftR\x0b\xd6\x021\xeb\xcb\xe4', b'\xd6z\xb3\x82\xe9J\xe9?:\xdcV\xcc\x0c\x82\xcb\xb8?\xbb\xfe\xf1S\xea\xe8?\xc5\x8d\x0e\xabgR\xb6\xa0\xb7S\x0c\xb3\x948\xb9\xe8\xef28\xdb\x07\x19\xee]>-\xaa\xea~\xc6\x84o\xa3\xb6\xf4\xb8 \x1c\x99\r', b'\x0f5LV\xab\xde\xf7\x9d-6\x19\xee\r\xfc\x91\xb8`]\xed\xb5\x13ftGI\x1e,-\xd4\x9e\xfd\xb1~B\xce\xee8X&\x83\xf4\x1f\xda\xa2\x0eu\x84\xec\xf1\x8e\x91b\xef\xd8@r\xd1\xb3u\x10D\x06\xbb\xad']]
    L = [[[75148441718093911093699265596595011891035690438045931474643057574137556167782, 84739144058733636519595151843306303651724619932316631317069372562615704548185], [36784820971120095994093557556704311148949345709377824388430505346592798585990, 16057742365979431381680357975770848778509610240762932265368682853282876069380], [94589466106114668891674682916584156112676760297700771796726523219520978530154, 57919896335080707081889889715128561100111063335759352388463264443091984563300]], [[99888744237355008543512857094857782212046167400882338507486491626237913195974, 60229276645013004795125227975056596894463495518335341750787980014400072638751], [78228094889104920350064451434167789844961074751446542911988684949760512615878, 89632181898210072562012896239884533880883773534592981556418433744667610213818], [13951688536512514926099771154175299040518332704493617534109449052874923310986, 3180525789243581493554610254111259482911904409848420939789486024828398114180]]]
    R = [[[80860683051483147187576854420906898390755022413253239943771056679123387775482, 23369161977150621357533360624103072826345397485256687996933763508054302582133], [101516620052698031207786929998565293167425704692177857430440012409146294700097, 59837914238284665309268481214172114692620528544936088448500386075512547468779], [62419719125379616810065053108781791752070492998926665605081560458471260653588, 75083362584239115944036822117242030411549246494018300357189133647871991406078]], [[98850925056643976589342831133144315891871273806432236154131296627848274500942, 102612949484613044425282162678712161683628369600970203512390545575002032217615], [15193103946820418931911127884882411771893802700442444795804210145590291664412, 97144336754426046402268193208155456246833216663576167369107625031362622450833], [40261957274494516514510507367774869457863765503612429855457568258645294224883, 95139970500591010011263820500155408332924226764272489553297701506603156186195]]]
send_ring("", matrix, c, ss, I)


# # test()