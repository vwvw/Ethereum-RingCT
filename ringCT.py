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
rangSigBool = True
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
        # 'y()',[])
        'testb(string,uint256,uint256,bytes32[2][],bytes32,uint256,uint256,bytes32[],uint256,bytes32[2][])',\
        [message,\
        len(pubkey), len(pubkey[0]), pubkeysAlligned,\
        c0,\
        len(ss), len(ss[0]), ssAlligned,\
        len(II), IIAlligned], gas=99999999999, gas_price=1)
    bashCommand = 'curl -X POST 127.0.0.1:8545 -m 3 --data ' + results.replace(" ", "")
    import subprocess
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    print(output)
    print("ERROR: ",error)
    print("------Transaction sent, waiting events-------")
    for i in range(0, 200):
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
    # x: bytes32 number
    # P1: pubkey in to string format bytes32
    # P2: pubkey in to string format bytes32

    if index == 0:
        a = to_32_bytes_number(random.randrange(crv.order))
        L1Point = g.from_string(a).verifying_key.pubkey.point
        s2 = to_32_bytes_number(random.randrange(crv.order))
        c2 = hashlib.sha256(to_32_bytes_number(L1Point.x()) + to_32_bytes_number(L1Point.y())).digest()
        L2Point = g.from_string(s2).verifying_key.pubkey.point + (VerifyingKey.from_string(P2).pubkey.point * to_int_from_bytes(c2))
        c1 = hashlib.sha256(to_32_bytes_number(L2Point.x()) + to_32_bytes_number(L2Point.y())).digest()
        s1 = to_32_bytes_number((to_int_from_bytes(a) -  to_int_from_bytes(x) * to_int_from_bytes(c1)) % crv.order)

        # sanity check
        if(debug):
            L1p = g.from_string(s1).verifying_key.pubkey.point + (VerifyingKey.from_string(P1).pubkey.point * to_int_from_bytes(c1))
            assert VerifyingKey.from_public_point(L1p).to_string() == VerifyingKey.from_public_point(L1Point).to_string(), \
                "Sanity check failed in GenSchnorr 1\nAborting..."
    if index == 1:
        a = to_32_bytes_number(random.randrange(crv.order))
        L2Point = g.from_string(a).verifying_key.pubkey.point
        s1 = to_32_bytes_number(random.randrange(crv.order))
        c1 = hashlib.sha256(to_32_bytes_number(L2Point.x()) + to_32_bytes_number(L2Point.y())).digest()
        L1Point = g.from_string(s1).verifying_key.pubkey.point + (VerifyingKey.from_string(P1).pubkey.point * to_int_from_bytes(c1))
        c2 = hashlib.sha256(to_32_bytes_number(L1Point.x()) + to_32_bytes_number(L1Point.y())).digest()
        s2 = to_32_bytes_number((to_int_from_bytes(a) - (to_int_from_bytes(x) * to_int_from_bytes(c2))) % crv.order)
        # sanity check
        if(debug):
            L2p = g.from_string(s2).verifying_key.pubkey.point + (VerifyingKey.from_string(P2).pubkey.point * to_int_from_bytes(c2))
            assert VerifyingKey.from_public_point(L2p).to_string() == VerifyingKey.from_public_point(L2Point).to_string(), \
                "Sanity check failed in GenSchnorr 2\nAborting..."
    L1 = VerifyingKey.from_public_point(L1Point).to_string()
    return L1, s1, s2

def VerSchnorrNonLinkable(P1, P2, L1, s1, s2):
    # P1: Pubkey in from_string format (32 bytes)
    # P2: Pubkey in from_string format (32 bytes)
    # L1: output of GenSchnorr, pubkey in from_string format (32 bytes)
    # s1: output of GenSchnorr, number (32 bytes)
    # s2: output of GenSchnorr, number (32 bytes)
    L1Point = VerifyingKey.from_string(L1).pubkey.point
    c2 = hashlib.sha256(to_32_bytes_number(L1Point.x()) + to_32_bytes_number(L1Point.y())).digest()
    L2PointA = g.from_string(s2).verifying_key.pubkey.point
    L2Point = g.from_string(s2).verifying_key.pubkey.point + (VerifyingKey.from_string(P2).pubkey.point * to_int_from_bytes(c2))
    c1 = hashlib.sha256(to_32_bytes_number(L2Point.x()) + to_32_bytes_number(L2Point.y())).digest()
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





# helloashjdagfghfhgjhjgjdlas = []
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

# if(upu == 0):
#     I = [b'q\xc0\x8bc2\x80\x80\xfb\xb7r2 \xf46\x0f\xbb\xed\x0e\xd6,\xe3\xd9S\x8e\xe7\xed@\xcc\x81\x0c8\x1c\xfd\xf2va3TR\x90m\x9c\n\n\xd8\x12\xd9,\xbc\xf5\x11\xef7ipg\xe8N0Y\x8ee\xdf%', b"\x8a\x85\xacWF_RG'2\x9bz\xf5\x15w\x01R\xf0Q(u\xbf\x18d\xc6\x04\x90\x91\n\xdf\x9c\x0b\x91\x02\x07\xc1\xfc\xb6\xc0D^S\x1b\xf0Q\xa3\x19Li\x9a\xed\x10\\\xdd\x9d\xac\xabqj\x13-4C\xfb", b'\x99y\xc9m\xefX\x1d\xebK\x1f\x0e`\x11d\xaaN\x9d*u\x87\x05}\x02\xc8\xcc@\x96\xfc\xbd\xa9v5l^\xb6(\x1a\x9f\xf7\xde\x84\x98\xfdyp\x0c\x9a\xb6\xdb1\xc6\x0c\x03@,\x0e\xb9k\xdaS\xc7\xb6\xff\xa9']
#     c = b"'\xf5V\xc5\xf2\x82)\x0f\x05\x9eA\xa2\x0f\xb9\x81\xe0\\\x12\xd4{\x15E\x8e\xfc\x12\xcb\x8ee)\x08\xabM"
#     ss = [[b'\xf4\xb1\xb9\x01\xe5\xe2lM\x0f\x8d\xf0\xbf\x7f\xdfy\xa8\xb0_\x0b\xe0\x0f\xf94\x16E\xf2V\xf2\xce\xd4[_', b'\xeag\xd84\xa3mg\xae\n\xdb2\xbc\xd3\xd8\xe4\xe9~W\x98\x1b\xe5\xa7\x96\x17\x0c\xb9\x1d\xc3\x85\xa7\x85\xb3', b',!\xdf\xf6\xa5\x92\x0e\x92\xeb]b{\xc4E\x80tA\xea\x0b\xd4\xfb9Y\xa1\x91{}\x01\x01\xd2\\\xe8'], [b'\x96:\xaa\xa1\xfd\xbaGb?\xa1@n^n~\xaadk\xd0L\xb0^GG\\\x01\x89\xfaq\xc8<u', b'\xf4\x0c\xd3\x1b,\xdf\n\x8cb}\xe5\x1cE\xe4\x00\xc4\xbc\xd1s\xc6\x89\x080%\x15x8`\xc6\x1an,', b'E\xbax\xba\xf9\x94\xff\r\xe3v\xa2i\x93\x05n\xdbv2\x9bd\x1a6\xcc\xaf\xc4\x1e\x8f,\xca\x07\x01\x1e']]
#     matrix = [[b'\x91%\xe8\xaf\xb0i\xfbh\xee9\x89&\x82\xa2\x0f\x15*\x92\x07\x9e\xf1\xc3\x84\xa5\xaa\xb6\xff_\x0c?a<j.?\x10x:F\xd8E\xd9\xad\x08t\x07\x8e|\x19\xf3\x87\xa7\x89\xe9\xaf~_\x00_b%;\x93\xd3', b"R\xa0\xc9_Z\x13\xbe\xb5\xe3r\xe4\xb7\na&\x9aQ\x8e>;A\x8b\xf3jg{\xf9Gg('\xdcf?\xbeY\x8e\xd7)\xd2W\xc4\x1bZI3-7\x9d\x1a\x19\xc6$>\xc8\xb5\xc0\x03F\x95\xef`y:", b'\x1a\x0f=\xc1\xa2\x90\xdb\n\xec\x1fVg5\xaf\xcf\xd9\xadTr\xdd\x03Z\x88-h\x12D\x06\xd6L\xfd@\x97\x15\xf3\x84uB\xd8\x18\xd1\xde\x18Z\x03\x9c\xf8+\xc2\x95\xb8OQc\x03>\xf0\xd6\xca/\x95\xd1b\xc0'], [b'\xd0\xa3\x91f\x80\xb6\x1dq\x1e\xefm\xbf\x08\x9f\xd6\xf0\xae\x86\xb7\xd8\xcc\xcd\xb4\x19\xd2\x82\xa4B\x9d\x8e\xe5\xd9\xe96H\x8b\r\x1d\xbeG\x14L0\xe4\x96\xf5\xef\xa1\xea\x89\xb5\xc3\x17\x84\xf7\xa9\x9fL\xe9\xfd?\xcc\xa4\x8d', b"~\xc0\x1d\xcdS+_\r\xec\xb6Ew\xac\n\xae;kyf\xcd\x00r\x11Mv \xc1`\xf5\x05f\x84\xb5\xf2)\xd8\x89~\xe7\x89\x8a\rIb\x15\x14#\x886e>\x03\x9d\xc6Y'\xaf\xb9\x96\x15\xcc\xaa\xeda", b'\x84\x90\x1f\xf9\x83\xdf\xdd\xc6\x91VE\x99\xe4[w\xe4\x04\x03,g@\xbb>F\xfb}\xf8\x9d\xff5&\xb3\x10.B\xb0\xe2\xde\x85\xbf\xe6R\xcb5\x99-\\\xe14\x92]l\x10\xf8\xe8\xfaB\xcf0\x84\x11\xe8\xf8N']]
#     L = [[[67568219278872063116858731286494094426526800021979047794231976327118747170869, 4124190802190768737775677903319986613278382390222016340637316022983215513951], [46641593214569842105539997646855453721704848548863602426668361867957162535410, 83491591937706361677055271494614659440509889704610681787481198916046399631745], [14173759417892718798002834245712052388429749841269886368695202810622651152182, 31373863148647571773452438583396577846309280139036828349113307581326624191833]], [[78801145352555159339513583962704496235407556387744775751375136652795140956258, 101092838777187931716179914931287066081957677419110531383717730505680516974757], [111448400435557596065604471457935035895276183210779941806004156927440360105758, 21255117225304034008510093823957577381882000064380536491866085372943723083579], [59361044430883609720657060515938544433618933260609749420965371432909223799009, 41554280199625242679513783979921334403875139778410686312899620239877156442268]]]
#     R = [[[88166592521677660875561116612873821404620222753600492098689398187623435611129, 34949305312588355594419135378409933446493941130282977849679070377922577585333], [79378051287249561629292263540481953767796307454786187664433011406507282425540, 49821777734207903760215127861024368170082158648811869920196480226167766133973], [38148449668158749289165377848720927370910678745245024081894245399513925718061, 74342531632521422242417623596467069192469074355442350577403624877306094188903]], [[5905088600175110656211302465017808401270270836803172573975504241952061909806, 57276724663561780559826149283786925648514763815542425453754812051511526033383], [30394712966506654142445613665813849351445412212753691625890997522176565299714, 66992915390068631033660621189564147531739819295224793360169282471566346754438], [101827451213677863453391062100079656748656651418103194190418965897085850185119, 14909169240030856436378977082027046791714731199379557039640355049357007351253]]]
# send_ring("", matrix, c, ss, I)

P1 = b"\xaddEd'\x9f\xef\xe1?&J\xc3\xb3CpT\x99\xeey\xd6\xfc\xf5\xb9\xcd\x0f,/\x06g\xe4\xa9\x83\xde\xca?X/\xab\x17\x16\xaco0S\xbe\xad<Hu\x00f8\x19\xcd\x00\xfd\x82O;Ic\xe0\x1e\x90"
P2 = b"\xd2n\x1c4n\x14\xc6\xd2i\x9c\xa1\x08\xf0\x04'G\xfd\x9b$\xc5\xf5\xf6\xf4\xe9\x94D\x99*o\x89P\x98\xc4\xd3Y\xd6E\xc8\x04\x9f\xc3\xde\x1d\x81\x82\xcd\x8f\x03)\x14\x1f\r\x08d\xfco\x83si7g;\xe1\xb4"
L1 = b"i\x90N\xc5\x1aYO*.F\xb71\x92V\xffCvT\x98\xb6C\xfaa#g\x14[\x13[\xab\x83\x99\xe6\x91{ \xee\xc8\\\xb4\xfd\x84}\xedG\x02\x126\xa0\x10\xb6\x11'|\xdf\xe3\xec\xbcw\xc26\xa3\x99\xee"
s1 = b'b\xdf0\xbe,\x1d\xdaj\x19Q\xa2\xdf\xee\xf6\x95\x0e\x80\xdc\xa2\xf8o\xe3$\xb89\x96j\xaf\xfa>\xce\xe6'
s2 = b'\x99ti\x8eO\xf1\xd6V\xcb\x1b6\xfe\x81\x97\r\xd9\xa3\x0ea\xc5t\x1d\x1ca[k\x8fD\x1a\x7f\x97;'
VerSchnorrNonLinkable(P1, P2, L1, s1, s2)
def sendSchnorr(P1, P2, L1, s1, s2):
    print("------ Preparing to send transaction  -------")
    filterNames = ['Log Error', 'Print string', 'Print bool', 'Print address', 'Print uint256', 'PrintStringAndUint(string,uint256)']
    to_keccack = ["LogErrorString(string)", "PrintString(string)", "PrintBool(bool)", "PrintAddress(address)", "PrintUint(uint256)", "PrintStringAndUint(string,uint256)"]
    keccack = []
    for i in range(0, len(to_keccack)):
        keccack.append(connection.web3_sha3(to_keccack[i]))

    filter = []
    for i in range(0, len(keccack)):
        filter.append(connection.eth_newFilter(from_block='earliest', address=contractAddress, topics=[keccack[i]]))

    cb = connection.eth_coinbase()
    P1P = VerifyingKey.from_string(P1).pubkey.point
    P1A = [P1P.x(), P1P.y()]
    P2P = VerifyingKey.from_string(P2).pubkey.point
    P2A = [P2P.x(), P2P.y()]
    L1P = VerifyingKey.from_string(L1).pubkey.point
    L1A = [L1P.x(), L1P.y()]
    results = connection.call_with_transaction(cb, contractAddress, 
        # 'y()',[])
        'VerSchnorrNonLinkable(uint256[2],uint256[2],uint256[2],bytes32,bytes32)',\
        [P1A, P2A, L1A, s1, s2], gas=99999999999, gas_price=1)
    bashCommand = 'curl -X POST 127.0.0.1:8545 -m 3 --data ' + results.replace(" ", "")
    import subprocess
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    print(output)
    print("ERROR: ",error)
    print("------Transaction sent, waiting events-------")
    for i in range(0, 20):
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
sendSchnorr(P1, P2, L1, s1, s2);

# # test()