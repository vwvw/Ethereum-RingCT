import random
from ecdsa import VerifyingKey
import sys
import time
import subprocess
from ethjsonrpc import EthJsonRpc

from .ringCT import (
    to_32_bytes_number,
    to_int_from_bytes,
    ecdh_encode,
    ecdh_decode,
    create_transaction,
    crv,
    g,
)

connection = EthJsonRpc("localhost", 8545)
truffle = True
timeTo = 1600
filterNames = [
    "Log Error",
    "Print string",
    "Print bool",
    "Print address",
    "Print uint256",
    "PrintStringAndUint(string,uint256)",
]
filters = []
to_keccack = [
    "LogErrorString(string)",
    "PrintString(string)",
    "PrintBool(bool)",
    "PrintAddress(address)",
    "PrintUint(uint256)",
    "PrintStringAndUint(string,uint256)",
]
pri = "07ca500a843616b48db3618aea3e9e1174dede9b4e94b95b2170182f632ad47c"
# noinspection SpellCheckingInspection
pub = (
    "0462abcca39e6dbe30ade7be2949239311162792bdb257f408ccd9eab65e18bc5bbcf8a3f08675bd792251a23d09a48a870644ba39"
    "23996cc5b5ec2d68043f3df3"
)


def prepare_arguments_to_send_ring(pubkey, c0, ss, II):
    """
    Prepare arguments for sending to the contract.
    Since solidity doesn't accept 2dim array so easily we have to adapt some of our arguments. C0 is untouched.
    :param pubkey:
    :param c0:
    :param ss:
    :param II:
    :return:
    """
    public_keys_aligned = []
    for i in range(0, len(pubkey)):
        for j in range(0, len(pubkey[0])):
            pk = VerifyingKey.from_string(pubkey[i][j], curve=crv).pubkey.point
            public_keys_aligned.append(
                [to_32_bytes_number(pk.x()), to_32_bytes_number(pk.y())]
            )

    ss_aligned = []
    for i in range(0, len(ss)):
        for j in range(0, len(ss[0])):
            ss_aligned.append(ss[i][j])

    IIAlligned = []
    for i in range(0, len(II)):
        I = VerifyingKey.from_string(II[i], curve=crv).pubkey.point
        IIAlligned.append([to_32_bytes_number(I.x()), to_32_bytes_number(I.y())])
    return public_keys_aligned, c0, ss_aligned, IIAlligned


def prepare_arguments_to_send_rg(range_signatures):
    """
    Prepare arguments for sending to the contract.
    Since solidity doesn't accept 2dim array so easily we have to adapt some of our arguments. C0 is untouched.
    :param range_signatures:
    :return:
    """
    n = len(range_signatures)
    CiArray = []
    L1Array = []
    s2_array = []
    s_array = []
    for i in range(0, n):
        s_array.append(to_int_from_bytes(range_signatures[i][1][2]))
        for j in range(0, len(range_signatures[i][0])):
            CiP = VerifyingKey.from_string(
                range_signatures[i][0][j], curve=crv
            ).pubkey.point
            CiArray.append([CiP.x(), CiP.y()])
            L1P = VerifyingKey.from_string(
                range_signatures[i][1][0][j], curve=crv
            ).pubkey.point
            L1Array.append([L1P.x(), L1P.y()])
            s2_array.append(to_int_from_bytes(range_signatures[i][1][1][j]))
    return CiArray, L1Array, s2_array, s_array


def display_filters():
    for i in range(0, timeTo):
        time.sleep(1)
        if i % 10 == 0:
            print(i)
    for i in range(0, len(filters)):
        change = connection.eth_getFilterChanges(filters[i])
        if len(change) > 0:
            for j in range(0, len(change)):
                if filterNames[i] == "Print uint256":
                    print(
                        filterNames[i]
                        + " result "
                        + str(j)
                        + ":\n"
                        + str(to_int_from_bytes(bytes.fromhex(change[j]["data"][2:])))
                    )
                else:
                    print(
                        filterNames[i]
                        + " result "
                        + str(j)
                        + ":\n"
                        + str(bytes.fromhex(change[j]["data"][2:]))
                    )

    print("------  All events have been displayed  ------")


def get_contract_address():
    contract_address = None
    with open("contract_address.txt") as f:
        content = f.readlines()
    content = [x.strip() for x in content]
    found = False
    i = 0
    while not found and i < len(content):
        if content[i][0:7] == "ringCT:":
            found = True
            contract_address = content[i][8:50]
        i += 1
    assert contract_address is not None
    if not found:
        sys.exit("Error message")
    return contract_address


def send(sig, args):
    """
    Send a function call to the contract
    :param sig: string of the signature of the function, no space, no variable name
    :param args: arguments in an array. In the order of the function signature.
    :return:
    """

    if truffle:
        results = connection.call_with_transaction(
            connection.eth_coinbase(),
            get_contract_address(),
            sig,
            args,
            gas=99999999999,
            gas_price=1,
        )
        bash_command = "curl -X POST 127.0.0.1:8545 -m 3 --data " + results.replace(
            " ", ""
        )
        process = subprocess.Popen(bash_command.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()
        print(output)
        print("ERROR: ", error)
        print("------ Transaction sent, waiting events ------")
        display_filters()


def send_transaction(message, matrix, I, c, ss, infos, rangeSig):
    # info are not used yet
    if truffle:
        print("------  Preparing to send Transaction   ------")
        public_keys_aligned, c0, ss_aligned, IIAlligned = prepare_arguments_to_send_ring(
            matrix, c, ss, I
        )
        CiArray, L1Array, s2_array, s_array = prepare_arguments_to_send_rg(rangeSig)

        # verify(string message, string info, uint256[2] pkDim, bytes32[2][] pkB, bytes32 c0, uint256[2] ssDim,
        # bytes32[] ssB, uint256 IIX, bytes32[2][] IIB, uint256[2] Cdim, uint256[2][] CiArray, uint256[2][] L1Array,
        # uint256[] s2_array, uint256[] s_array)
        sig = (
            "verify(string,string,uint256[2],bytes32[2][],bytes32,uint256[2],bytes32[],uint256,bytes32[2][],"
            "uint256[2],uint256[2][],uint256[2][],uint256[],uint256[])"
        )
        args = [
            message,
            infos,
            [len(matrix), len(matrix[0])],
            public_keys_aligned,
            c0,
            [len(ss), len(ss[0])],
            ss_aligned,
            len(I),
            IIAlligned,
            [len(rangeSig), len(rangeSig[0][0])],
            CiArray,
            L1Array,
            s2_array,
            s_array,
        ]
        send(sig, args)


def send_ring(message, pubkey, c0, ss, II):
    if truffle:
        print("------  Preparing to send transaction   ------")
        public_keys_aligned, c0, ss_aligned, IIAlligned = prepare_arguments_to_send_ring(
            pubkey, c0, ss, II
        )

        sig = (
            "verifySignature(string,uint256,uint256,bytes32[2][],bytes32,uint256,uint256,bytes32[],uint256,"
            "bytes32[2][])"
        )
        args = [
            message,
            len(pubkey),
            len(pubkey[0]),
            public_keys_aligned,
            c0,
            len(ss),
            len(ss[0]),
            ss_aligned,
            len(II),
            IIAlligned,
        ]
        send(sig, args)


def send_rg(range_signature):
    if truffle:
        print("------  Preparing to send Transaction   ------")
        CiArray, L1Array, s2_array, s_array = prepare_arguments_to_send_rg(
            range_signature
        )
        # verifyRangeProofs(uint256 Cx, uint256 Cy, uint256[2][] CiArray, uint256[2][] L1Array, uint256[] s2_array,
        # uint256[] sArray)
        sig = "verifyRangeProofs(uint256,uint256,uint256[2][],uint256[2][],uint256[],uint256[])"
        args = [
            len(range_signature),
            len(range_signature[0][0]),
            CiArray,
            L1Array,
            s2_array,
            s_array,
        ]
        send(sig, args)


def sendASNL(P1, P2, L1, s2, s):
    if truffle:
        print("------  Preparing to send ASNL   ------")
        P1x = len(P1)
        P1A = [
            [
                VerifyingKey.from_string(x, curve=crv).pubkey.point.x(),
                VerifyingKey.from_string(x, curve=crv).pubkey.point.y(),
            ]
            for x in P1
        ]
        P2A = [
            [
                VerifyingKey.from_string(x, curve=crv).pubkey.point.x(),
                VerifyingKey.from_string(x, curve=crv).pubkey.point.y(),
            ]
            for x in P2
        ]
        L1A = [
            [
                VerifyingKey.from_string(x, curve=crv).pubkey.point.x(),
                VerifyingKey.from_string(x, curve=crv).pubkey.point.y(),
            ]
            for x in L1
        ]
        s2a = [to_int_from_bytes(x) for x in s2]

        sig = "verify_ASNL(uint256,uint256[2][],uint256[2][],uint256[2][],uint256[],uint256)"
        args = [P1x, P1A, P2A, L1A, s2a, to_int_from_bytes(s)]
        send(sig, args)


def send_verify_range_signatures(P1, L1, s2, s):
    if truffle:
        print("------  Preparing to send VerRang   ------")
        P1A = [
            [
                VerifyingKey.from_string(x, curve=crv).pubkey.point.x(),
                VerifyingKey.from_string(x, curve=crv).pubkey.point.y(),
            ]
            for x in P1
        ]
        L1A = [
            [
                VerifyingKey.from_string(x, curve=crv).pubkey.point.x(),
                VerifyingKey.from_string(x, curve=crv).pubkey.point.y(),
            ]
            for x in L1
        ]
        s2A = [to_int_from_bytes(x) for x in s2]
        sig = "verify_range_proofs(uint256[2][],uint256[2][],uint256[],uint256)"
        args = [P1A, L1A, s2A, to_int_from_bytes(s)]
        send(sig, args)


def test():
    print("------   Entering the first test case.  ------")
    for i in range(0, 10):
        x = random.randrange(2 ** 256)
        assert x == to_int_from_bytes(
            to_32_bytes_number(x)
        ), "bytes <-> int conversion failed, x = {}".format(x)

    print("------  Entering the second test case.  ------")

    for i in range(0, 10):
        x = random.randrange(crv.order)
        y = random.randrange(crv.order)
        new_mask, new_amount, send_public_key = ecdh_encode(
            to_32_bytes_number(x), to_32_bytes_number(y), bytes.fromhex(pub)
        )
        new_x, new_y = ecdh_decode(
            new_mask, new_amount, send_public_key, bytes.fromhex(pri)
        )
        assert (
            to_int_from_bytes(new_x) == x and to_int_from_bytes(new_y) == y
        ), "ECDH failed, x = {}, y = {}".format(x, y)

    print("------   All test passed. Well done !   ------")


def main():
    if truffle:
        keccack = []
        for i in range(0, len(to_keccack)):
            keccack.append(connection.web3_sha3(to_keccack[i]))
        for i in range(0, len(keccack)):
            filters.append(
                connection.eth_newFilter(
                    from_block="earliest",
                    address=get_contract_address(),
                    topics=[keccack[i]],
                )
            )

    # sample private and public keys used for testing
    # noinspection SpellCheckingInspection
    pri4 = "79d3372ffd4278affd69313355d38c6d90d489e4ab0bbbef9589d7cc9559ab6d"
    pri5 = "00dff8928e99bda9bb83a377e09c8bf5d110c414fa65d771b7b84797709c7dd0b1"
    # noinspection SpellCheckingInspection
    pub2 = (
        "040ccad48919d8f6a206a1ac7113c22db62aa744a0700762b70aa0284d474c00203029637ce8e84f6551fd92a0db8e1f964ff13aa"
        "992e4cbfd1fb8fa33c6e6c53c"
    )
    # noinspection SpellCheckingInspection
    pub3 = (
        "049f742f925b554e2dc02e2da5cb9663ef810e9eefb30818b3c12bc26afb8dd7ba3461c0f7d2b997bf455973af308a71ed34ae415"
        "cfc946de84db3961db522e5d2"
    )
    # noinspection SpellCheckingInspection
    pub4 = (
        "04ef36c6d140e7970cc54c08e0e5d3173059ee6276dd0de99e09d10c49bd49e63c44e0a2e7180fff5e3e8a549027b8a37bc3a9437"
        "374ef1b7a05040b244a7bccc5"
    )
    # noinspection SpellCheckingInspection
    pub5 = (
        "04da11a42320ae495014dd9c1c51d43d6c55ca51b7fe9ae3e1258e927e97f48be4e7a4474c067154fdaa1c5b26dee555c3e649337"
        "605510cf9e1d5c1e657352e9c"
    )
    # createTransaction(bytes.fromhex(pri), bytes.fromhex(pub), [bytes.fromhex(pub2), bytes.fromhex(pub3)], [1, 2], 2)

    in_amounts = [3, 4]
    in_sk = []
    in_pk = []
    for i in range(0, len(in_amounts)):
        sk = to_32_bytes_number(random.randrange(crv.order))
        in_sk.append(sk)
        in_pk.append(g.from_string(sk, curve=crv).verifying_key.to_string())

    out_amount = [1, 6]
    message = "hello"
    out_public_key = [
        VerifyingKey.from_string(bytes.fromhex(pub)[1:], curve=crv).to_string(),
        VerifyingKey.from_string(bytes.fromhex(pub5)[1:], curve=crv).to_string(),
    ]
    matrix, destinations, destinations_commitment, I, c, ss, info, range_signatures = create_transaction(
        message, in_pk, in_sk, in_amounts, out_public_key, out_amount, 2
    )

    send_transaction(message, matrix, I, c, ss, "", range_signatures)


if __name__ == "__main__":
    main()
