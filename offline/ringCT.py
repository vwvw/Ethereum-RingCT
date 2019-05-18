import random
import hashlib
import sha3
import binascii
import ecdsa
from ecdsa import SigningKey, VerifyingKey
from ecdsa.ellipticcurve import Point


# Flags to accelerate debugging
debug = True
rang_sig_bool = True

MAX_AMOUNT = 2 ** 64
MAX_MIXIN = 10
crv = ecdsa.SECP256k1  # need to be passed to 1
g = SigningKey.generate(curve=crv)
P = 2 ** 256 - 2 ** 32 - 2 ** 9 - 2 ** 8 - 2 ** 7 - 2 ** 6 - 2 ** 4 - 1
G = (
    "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554"
    "199C47D08FFB10D4B8"
)
curveOrder = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
ATOMS = 64


def hash_to_point(public_key):
    """
    Takes a public key, hash it and convert the hash to a valid point. This is achieved by taking the hash as the secret
    exponent of a new public key.
    :param public_key: the representation of the public key
    :return:
    """
    return g.from_string(hashlib.sha256(public_key).digest(), curve=crv).verifying_key


def hash_to_point_special(pub_key):
    """
    Hash a public key by first adding the two integers that compose it.
    :param pub_key:
    :return:
    """
    p = VerifyingKey.from_string(pub_key, curve=crv).pubkey.point
    return hash_to_point(to_32_bytes_number(p.x()) + to_32_bytes_number(p.y()))


def to_32_bytes_number(val, endianness="big"):
    """
    Convert an integer to its bytes representation (32 bytes).
    See https://stackoverflow.com/questions/8730927/convert-python-long-int-to-fixed-size-byte-array/28057222
    :param val: decimal number to transform.
    :param endianness: string 'big' or 'little' depending on the endianness wanted.
    :return: the number in the 32 bytes format.
    """
    fmt = "%%0%dx" % 64
    s = binascii.unhexlify(fmt % val)
    if endianness == "little":
        # see http://stackoverflow.com/a/931095/309233
        s = s[::-1]
    return s


def to_int_from_bytes(val, endianness="big"):
    """
    Inverse of to_32_bytes_number. Convert a 32 bytes number to its integer representation.
    :param val: the 32 bytes number to transform.
    :param endianness: string 'big' or 'little' depending on the endianness wanted.
    :return: the number as an int
    """
    return int.from_bytes(val, byteorder=endianness)


def add_2_32b(a, b):
    """
    Add two integers from their 32 bytes representation.
    :param a: first number
    :param b: second number
    :return: a 32 bytes representation of the result.
    """
    return to_32_bytes_number((to_int_from_bytes(a) + to_int_from_bytes(b)) % crv.order)


def sub_2_32b(a, b):
    """
    Subtract two 32 bytes number
    :param a: the initial value as a 32 bytes number.
    :param b: the value to subtract as a 32 bytes number.
    :return: the resulting value as a 32 bytes number.
    """
    return to_32_bytes_number((to_int_from_bytes(a) - to_int_from_bytes(b)) % crv.order)


def ecdh_encode(mask, amount, receiver_public_key):
    """
    This function encode the a number (the amount) so that it can only be decoded with the receiver private key.
    Amount is however only masked, calculation can still be applied on it.

    :param mask: the mask to hide (32 bytes number)
    :param amount: the amount to hide (32 bytes number)
    :param receiver_public_key: the receiver public key (sec format)
    :return: a triplet of new_mask: hidden mask (32 bytes number)
                          new_amount: hidden amount (32 bytes number)
                          sender_public_key: the public key generated by the sender to encode this amount (sec format)

    """
    secret = to_32_bytes_number(random.randrange(crv.order))
    sender_secret_key = g.from_string(secret, curve=crv)
    sender_public_key = sender_secret_key.verifying_key
    recv_public_key = VerifyingKey.from_string(receiver_public_key, curve=crv)
    to_hash = VerifyingKey.from_public_point(
        recv_public_key.pubkey.point * to_int_from_bytes(secret), curve=crv
    ).to_string()
    shared_secret_int = to_int_from_bytes(hashlib.sha256(to_hash).digest())
    new_mask = (to_int_from_bytes(mask) + shared_secret_int) % crv.order
    new_amount = (to_int_from_bytes(amount) + shared_secret_int) % crv.order
    return (
        to_32_bytes_number(new_mask),
        to_32_bytes_number(new_amount),
        sender_public_key.tpo_string(),
    )


def ecdh_decode(mask, amount, sender_public_key, receiver_secret_key):
    """
    Function doing the decoding of ecdhEncode. Take the mask, the masked amount and appropriate public keys and return
    the decoded amount.
    :param mask: the hidden mask (32 bytes number)
    :param amount: the hidden amount (32 bytes number)
    :param sender_public_key: the public key generated by the sender to encode this amount (sec format)
    :param receiver_secret_key: the receiver sk (32 bytes number)
    :return: tuple consisting of new_mask: unhidden mask (32 bytes number)
                                 new_amount: unhidden amount (32 bytes number)
    """

    send_public_key = VerifyingKey.from_string(sender_public_key, curve=crv)
    to_hash = VerifyingKey.from_public_point(
        send_public_key.pubkey.point * to_int_from_bytes(receiver_secret_key), curve=crv
    ).to_string()
    shared_secret_int = to_int_from_bytes(hashlib.sha256(to_hash).digest())
    new_mask = (to_int_from_bytes(mask) - shared_secret_int) % crv.order
    new_amount = (to_int_from_bytes(amount) - shared_secret_int) % crv.order
    return to_32_bytes_number(new_mask), to_32_bytes_number(new_amount)


def create_transaction(
    message, in_public_key, in_secret_key, in_amounts, destinations, out_amounts, mixin
):
    """

    :param message:
    :param in_public_key: vector of public keys corresponding to the owner inputs(sec format)
    :param in_secret_key: vector of private keys corresponding to the public keys (format 32bytes number)
    :param in_amounts: vector of number corresponding to the amount coming from corresponding public key
    :param destinations: vector of public keys (sec format)
    :param out_amounts: vector of the different amounts going to the respective destinations public keys (int)
    :param mixin: the number of pk to get involved in the rings (int)
    :return: a list composed of destinations: a vector of destinations public keys as received (sec format)
                                destinations_commitment: a vector of commitment assigned to each
                                                        destinations public keys (32 bytes numbers)
                                I: part of MLSAG, a vector of pk in sec format corresponding the the sha256 hash of the
                                   sender public key
                                c_0: part of MLSAG, first sha3_256 (keccack) of the consecutive series of the MLSAG
                                ss: part of MLSAG, a matrix of "random" 32 bytes number
                                info: an array of ecdhEncode result containing the amount paid to the
                                       corresponding output pk
                                range_signatures: vector of range_signatures (format TODO)
    """

    print("------  Let's create a the transaction  ------")
    assert 0 < mixin < MAX_MIXIN, (
        "The number of ring participant should be between 0 and "
        + str(MAX_MIXIN)
        + "\n Aborting..."
    )
    assert len(in_secret_key) == len(in_public_key) and len(in_amounts) == len(
        in_public_key
    ), "The number of private key doesn't match the number of public key or the number of input amounts.\nAborting..."
    assert len(destinations) == len(
        out_amounts
    ), "The number of outputs addresses should match the number of outputs amounts.\nAborting..."
    m = len(in_secret_key)
    for i in range(0, m):
        assert 0 < in_amounts[i] < MAX_AMOUNT, (
            "The ingoing amount #"
            + str(i)
            + " should be between 0 and "
            + str(MAX_AMOUNT)
            + "\nAborting..."
        )
    out_num = len(destinations)
    for i in range(0, out_num):
        assert 0 < out_amounts[i] < MAX_AMOUNT, (
            "The outgoing amount #"
            + str(i)
            + " should be between 0 and "
            + str(MAX_AMOUNT)
            + "\nAborting..."
        )

    for i in range(0, m):
        assert (
            g.from_string(in_secret_key[i], curve=crv).verifying_key.to_string()
            == in_public_key[i]
        ), "One secret key doesn't match the corresponding public key.\nAborting..."

    print("------  All arguments are good, next !  ------")

    in_sk_masks = []
    in_pk_masks = []
    for i in range(0, m):
        sk_mask = to_32_bytes_number(random.randrange(crv.order))
        in_sk_masks.append(sk_mask)
        pk_mask = g.from_string(sk_mask, curve=crv).verifying_key
        a_h = hash_to_point(to_32_bytes_number(1)).pubkey.point * in_amounts[i]
        pk_mask_point = pk_mask.pubkey.point + a_h
        in_pk_masks.append(
            VerifyingKey.from_public_point(pk_mask_point, curve=crv).to_string()
        )

    destinations_commitment = []
    info = []
    range_signatures = []
    out_sk_masks = []
    for i in range(0, out_num):
        print("------ Creating rangeproof for amount#" + str(i + 1) + " ------")
        out_commit, out_sk_mask, rg = prove_range_signatures(out_amounts[i])
        destinations_commitment.append(out_commit)
        out_sk_masks.append(out_sk_mask)
        range_signatures.append(rg)
        hidden_mask, hidden_amount, sender_pk = ecdh_encode(
            out_sk_mask, to_32_bytes_number(out_amounts[i]), destinations[i]
        )
        info.append([hidden_mask, hidden_amount, sender_pk])

    print("------   Rangeproofs are valid. Next    ------")

    pk_matrix, pk_masks_matrix, index = populate_from_blockchain(
        in_public_key, in_pk_masks, mixin
    )

    print("------ Matrix populated, going further! ------")

    if debug:
        (newMatrix, (I, c_0, ss)) = prepareMG(
            message,
            pk_matrix,
            pk_masks_matrix,
            in_secret_key,
            in_sk_masks,
            destinations_commitment,
            out_sk_masks,
            index,
        )
        print("------ Transaction created with succes! ------")
        return (
            newMatrix,
            destinations,
            destinations_commitment,
            I,
            c_0,
            ss,
            info,
            range_signatures,
        )
    else:
        (newMatrix, (I, c_0, ss)) = prepareMG(
            message,
            pk_matrix,
            pk_masks_matrix,
            in_secret_key,
            in_sk_masks,
            destinations_commitment,
            out_sk_masks,
            index,
        )
        print("------ Transaction created with succes! ------")
        return (
            newMatrix,
            destinations,
            destinations_commitment,
            I,
            c_0,
            ss,
            info,
            range_signatures,
        )


def verify_transaction(message, new_matrix, I, c_0, ss, infos, range_signatures):
    for rg in range_signatures:
        verify_range_proofs(rg)
    verifyMG(message, new_matrix, I, c_0, ss)


def prepareMG(
    message,
    public_keys,
    public_key_commitments,
    in_sk,
    in_sk_mask,
    out_commitment,
    out_sk_masks,
    index,
):
    """

    :param message:
    :param public_keys: matrix of public key (size: qxm, sec format)
    :param public_key_commitments: matrix of commitment for pk (size: qxm, 32bytes)
    :param in_sk: vector of private key (size: m, bytes32 format)
    :param in_sk_mask: vector of mask for the corresponding sk (size: m, 32bytes)
    :param out_commitment: vector of commitment for pk (hidden amount) (size: outPKsize, 32bytes)
    :param out_sk_masks: vector mask for out public keys (bytes32)
    :param index: index of where in the public_keys matrix our pks are located
    :return: same as gen_MG
    """

    print("------  Preparing the matrix for the MG ------")

    rows_q = len(public_keys)
    if debug:
        assert (
            len(public_keys) == len(public_key_commitments) and len(public_keys) > 0
        ), "\
            Mismatch in the number of public commitment and keys.\nAborting..."
    cols_m = len(public_keys[0])
    if debug:
        assert (
            len(in_sk) == len(in_sk_mask) and len(in_sk) == cols_m
        ), "Mismatch in the number of private keys or private key masks.\nAborting..."
        for i in range(0, rows_q):
            assert (
                len(public_keys[i]) == len(public_key_commitments[i])
                and len(public_keys[i]) == cols_m
            ), "Mismatch in the number of public commitment and keys.\nAborting..."
        assert 0 <= index < rows_q, (
            "index: "
            + str(index)
            + " should be between 0 and "
            + str(rows_q)
            + " (the number of public key).\nAborting..."
        )
        assert (
            len(out_commitment) == len(out_sk_masks) and len(out_commitment) > 0
        ), "Mismatch in the number of private commitment and keys.\nAborting..."

    matrix = [[None] * (cols_m + 1) for y in range(rows_q)]
    sk = [None] * (cols_m + 1)
    for i in range(cols_m):
        sk[i] = in_sk[i]
        if i == 0:
            sk[cols_m] = in_sk_mask[i]
        else:
            sk[cols_m] = add_2_32b(sk[cols_m], in_sk_mask[i])
        for j in range(rows_q):
            matrix[j][i] = public_keys[j][i]
            if i == 0:
                matrix[j][cols_m] = VerifyingKey.from_string(
                    public_key_commitments[j][i], curve=crv
                ).pubkey.point
            else:
                matrix[j][cols_m] = (
                    matrix[j][cols_m]
                    + VerifyingKey.from_string(
                        public_key_commitments[j][i], curve=crv
                    ).pubkey.point
                )

    for i in range(len(out_commitment)):
        sk[cols_m] = sub_2_32b(sk[cols_m], out_sk_masks[i])
    for i in range(rows_q):
        for j in range(len(out_commitment)):
            point = VerifyingKey.from_string(out_commitment[j], curve=crv).pubkey.point
            matrix[i][cols_m] = (
                matrix[i][cols_m]
                + VerifyingKey.from_public_point(
                    Point(
                        crv.curve, point.x(), (-point.y()) % crv.curve.p(), crv.order
                    ),
                    curve=crv,
                ).pubkey.point
            )

    for j in range(rows_q):
        matrix[j][cols_m] = VerifyingKey.from_public_point(
            matrix[j][cols_m], curve=crv
        ).to_string()

    print("------  Done with the matrix for the MG ------")

    # TODO message
    return matrix, genMG(message, matrix, sk, index)


def list_to_bytes(list_of_int):
    # [[None, None] for x in range(m)]
    ret = to_32_bytes_number(list_of_int[0][0]) + to_32_bytes_number(list_of_int[0][1])
    for x in range(1, len(list_of_int)):
        ret += to_32_bytes_number(list_of_int[x][0]) + to_32_bytes_number(
            list_of_int[x][1]
        )
    return ret


def genMG(message, matrix, sk, index):

    n = len(matrix)
    if debug:
        assert n > 0, "No public key received.\nAborting..."
    m = len(matrix[0])
    if debug:
        assert m == len(
            sk
        ), "The number of secret key doesn't match the number of public key.\nAborting..."
        for i in range(0, n):
            assert (
                len(matrix[i]) == m
            ), "Public key array is not rectangular.\nAborting..."
        assert m > 0, "No public key in the array.\nAborting..."
        assert 0 <= index < m, "Not a valid index.\nAborting..."
        for i in range(0, m):
            assert (
                g.from_string(sk[i], curve=crv).verifying_key.to_string()
                == matrix[index][i]
            ), (
                "One secret key doesn't match the public key. Index: "
                + str(i)
                + "\n\
                Aborting..."
            )

    message_bytes = bytes(message, "UTF-8")

    alpha = [None] * m
    I = [None] * m
    ss = [[None] * m] * n

    L = [[[None, None]] * m] * n
    R = [[[None, None]] * m] * n

    for j in range(0, m):
        sk_j_hash_pub_point = hash_to_point(
            matrix[index][j]
        ).pubkey.point * to_int_from_bytes(sk[j])
        I[j] = VerifyingKey.from_public_point(
            sk_j_hash_pub_point, curve=crv
        ).to_string()

        alpha[j] = to_32_bytes_number(random.randrange(crv.order))
        LPoint = g.from_string(alpha[j], curve=crv).verifying_key.pubkey.point
        L[index][j] = [LPoint.x(), LPoint.y()]

        alpha_hash_pub_point = hash_to_point_special(
            matrix[index][j]
        ).pubkey.point * to_int_from_bytes(alpha[j])
        R[index][j] = [alpha_hash_pub_point.x(), alpha_hash_pub_point.y()]

    c_idx_1 = sha3.keccak_256(
        message_bytes + list_to_bytes(L[index]) + list_to_bytes(R[index])
    ).digest()

    c = c_idx_1
    c_0 = None
    for i in range(1, n):
        idx = (index + i) % n
        for j in range(0, m):
            # assert ss[idx][j] == None, "Hmm sounds bad"
            ss[idx][j] = to_32_bytes_number(random.randrange(crv.order))

            c_PubK = VerifyingKey.from_string(
                matrix[idx][j], curve=crv
            ).pubkey.point * to_int_from_bytes(c)
            sj_G = g.from_string(ss[idx][j], curve=crv)
            L_point = c_PubK + sj_G.verifying_key.pubkey.point
            L[idx][j] = [L_point.x(), L_point.y()]

            c_I = VerifyingKey.from_string(
                I[j], curve=crv
            ).pubkey.point * to_int_from_bytes(c)
            R_point = (
                hash_to_point_special(matrix[idx][j]).pubkey.point
                * to_int_from_bytes(ss[idx][j])
                + c_I
            )
            R[idx][j] = [R_point.x(), R_point.y()]

        c = sha3.keccak_256(
            message_bytes + list_to_bytes(L[idx]) + list_to_bytes(R[idx])
        ).digest()
        if idx == n - 1:
            c_0 = c

    print("------  Done with generating the MLSAG  ------")

    if debug:
        # sanity check:
        L_tmp = [[None, None]] * m
        R_tmp = [[None, None]] * m

        for j in range(0, m):
            ss[index][j] = to_32_bytes_number(
                (
                    to_int_from_bytes(alpha[j])
                    - to_int_from_bytes(c) * to_int_from_bytes(sk[j])
                )
                % crv.order
            )

            c_PubK = VerifyingKey.from_string(
                matrix[index][j], curve=crv
            ).pubkey.point * to_int_from_bytes(c)
            sj_G = g.from_string(ss[index][j], curve=crv)
            L_point = c_PubK + sj_G.verifying_key.pubkey.point
            L_tmp[j] = [L_point.x(), L_point.y()]

            c_I = VerifyingKey.from_string(
                I[j], curve=crv
            ).pubkey.point * to_int_from_bytes(c)
            R_point = (
                hash_to_point_special(matrix[index][j]).pubkey.point
                * to_int_from_bytes(ss[index][j])
                + c_I
            )
            R_tmp[j] = [R_point.x(), R_point.y()]

        c_tmp = sha3.keccak_256(
            message_bytes + list_to_bytes(L_tmp) + list_to_bytes(R_tmp)
        ).digest()
        assert (
            L_tmp == L[index] and R_tmp == R[index]
        ), "Sanity check for computing ss[index] failed.\nAborting..."

    if debug:
        assert verifyMG(
            message, matrix, I, c_0, ss
        ), "Ring verification failed.\nAborting..."
        print("------  Done with verifying the MLSAG   ------")
        return I, c_0, ss
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
    assert len(I) == len(
        ss[0]
    ), "Not the same number of pubkey hash (I) as of secret (ss)."

    message_bytes = bytes(message, "UTF-8")

    L = [[[None, None]] * m] * n
    R = [[[None, None]] * m] * n

    c = c_0
    for idx in range(0, n):
        for j in range(0, m):
            # print("------ " + str(idx * m + j) + "")
            c_PubK = VerifyingKey.from_string(
                matrix[idx][j], curve=crv
            ).pubkey.point * to_int_from_bytes(c)
            sj_G = g.from_string(ss[idx][j], curve=crv)
            L_point = c_PubK + sj_G.verifying_key.pubkey.point
            L[idx][j] = [L_point.x(), L_point.y()]

            c_I = VerifyingKey.from_string(
                I[j], curve=crv
            ).pubkey.point * to_int_from_bytes(c)
            p = hash_to_point_special(matrix[idx][j]).pubkey.point * to_int_from_bytes(
                ss[idx][j]
            )
            R_point = p + c_I
            R[idx][j] = [R_point.x(), R_point.y()]

        c = sha3.keccak_256(
            message_bytes + list_to_bytes(L[idx]) + list_to_bytes(R[idx])
        ).digest()
    return c == c_0


def populate_from_blockchain(public_key, in_public_key_masks, mixin):
    """

    :param public_key: vector of public keys, sec format
    :param in_public_key_masks: vector of bytes32 (format from verifyingkey.to_string())
    :param mixin: number of other public key to involve.
    :return: a triple of public_key_matrix: matrix of public keys in sec format
                         mask_matrix: the corresponding matrix containing the masks
                         index: the index of our pk in the matrix
    """

    if debug:
        assert len(public_key) == len(
            in_public_key_masks
        ), "Mismatch in the number of public key and their corresponding mask\n\
            Aborting..."
    m = len(public_key)
    index = random.randrange(mixin - 1)
    pk_matrix = []
    mask_matrix = []
    for i in range(0, mixin):
        if i != index:
            pk_matrix.append([get_key_from_blockchain() for i in range(0, m)])
            mask_matrix.append(
                [
                    hash_to_point(
                        to_32_bytes_number(random.randrange(crv.order))
                    ).to_string()
                    for i in range(0, m)
                ]
            )
        else:
            pk_matrix.append(public_key)
            mask_matrix.append(in_public_key_masks)
    return pk_matrix, mask_matrix, index


def get_key_from_blockchain():
    """
    Fetch possible public key from the blockchain to put in our ring signature. NOT IMPLEMENTED YET
    :return: a public key "from the blockchain" in the to_string format
    """
    # TODO
    x = to_32_bytes_number(random.randrange(crv.order))
    return g.from_string(x, curve=crv).verifying_key.to_string()


def generate_schnorr_non_linkable(x, P1, P2, index):
    """

    :param x: 32 bytes number
    :param P1: public key (format string of bytes32 representation)
    :param P2: public key (format string of bytes32 representation)
    :param index: random value
    :return:
    """
    # x: bytes32 number
    # P1: pubkey in to string format bytes32
    # P2: pubkey in to string format bytes32

    if not index:
        a = to_32_bytes_number(random.randrange(crv.order))
        L1Point = g.from_string(a, curve=crv).verifying_key.pubkey.point
        s2 = to_32_bytes_number(random.randrange(crv.order))
        c2 = hashlib.sha256(
            to_32_bytes_number(L1Point.x()) + to_32_bytes_number(L1Point.y())
        ).digest()
        L2Point = g.from_string(s2, curve=crv).verifying_key.pubkey.point + (
            VerifyingKey.from_string(P2, curve=crv).pubkey.point * to_int_from_bytes(c2)
        )
        c1 = hashlib.sha256(
            to_32_bytes_number(L2Point.x()) + to_32_bytes_number(L2Point.y())
        ).digest()
        s1 = to_32_bytes_number(
            (to_int_from_bytes(a) - to_int_from_bytes(x) * to_int_from_bytes(c1))
            % crv.order
        )

        # sanity check
        if debug:
            L1p = g.from_string(s1, curve=crv).verifying_key.pubkey.point + (
                VerifyingKey.from_string(P1, curve=crv).pubkey.point
                * to_int_from_bytes(c1)
            )
            assert (
                VerifyingKey.from_public_point(L1p, curve=crv).to_string()
                == VerifyingKey.from_public_point(L1Point, curve=crv).to_string()
            ), "Sanity check failed in GenSchnorr 1\nAborting..."

    if index:
        a = to_32_bytes_number(random.randrange(crv.order))
        L2Point = g.from_string(a, curve=crv).verifying_key.pubkey.point
        s1 = to_32_bytes_number(random.randrange(crv.order))
        c1 = hashlib.sha256(
            to_32_bytes_number(L2Point.x()) + to_32_bytes_number(L2Point.y())
        ).digest()
        L1Point = g.from_string(s1, curve=crv).verifying_key.pubkey.point + (
            VerifyingKey.from_string(P1, curve=crv).pubkey.point * to_int_from_bytes(c1)
        )
        c2 = hashlib.sha256(
            to_32_bytes_number(L1Point.x()) + to_32_bytes_number(L1Point.y())
        ).digest()
        s2 = to_32_bytes_number(
            (to_int_from_bytes(a) - (to_int_from_bytes(x) * to_int_from_bytes(c2)))
            % crv.order
        )
        # sanity check
        if debug:
            L2p = g.from_string(s2, curve=crv).verifying_key.pubkey.point + (
                VerifyingKey.from_string(P2, curve=crv).pubkey.point
                * to_int_from_bytes(c2)
            )
            assert (
                VerifyingKey.from_public_point(L2p, curve=crv).to_string()
                == VerifyingKey.from_public_point(L2Point, curve=crv).to_string()
            ), "Sanity check failed in GenSchnorr 2\nAborting..."
    L1 = VerifyingKey.from_public_point(L1Point, curve=crv).to_string()
    return L1, s1, s2


def verify_schnorr_non_linkable(P1, P2, L1, s1, s2):
    # P1: Pubkey in from_string format (32 bytes)
    # P2: Pubkey in from_string format (32 bytes)
    # L1: output of GenSchnorr, pubkey in from_string format (32 bytes)
    # s1: output of GenSchnorr, number (32 bytes)
    # s2: output of GenSchnorr, number (32 bytes)
    L1Point = VerifyingKey.from_string(L1, curve=crv).pubkey.point
    c2 = hashlib.sha256(
        to_32_bytes_number(L1Point.x()) + to_32_bytes_number(L1Point.y())
    ).digest()
    L2PointA = g.from_string(s2, curve=crv).verifying_key.pubkey.point
    L2Point = g.from_string(s2, curve=crv).verifying_key.pubkey.point + (
        VerifyingKey.from_string(P2, curve=crv).pubkey.point * to_int_from_bytes(c2)
    )
    c1 = hashlib.sha256(
        to_32_bytes_number(L2Point.x()) + to_32_bytes_number(L2Point.y())
    ).digest()
    L1p = VerifyingKey.from_public_point(
        g.from_string(s1, curve=crv).verifying_key.pubkey.point
        + (
            VerifyingKey.from_string(P1, curve=crv).pubkey.point * to_int_from_bytes(c1)
        ),
        curve=crv,
    ).to_string()
    assert (
        L1 == L1p
    ), "generate_schnorr_non_linkable failed to generate a valid signature.\nAborting..."


def generate_ASNL(x, P1, P2, indices):
    """

    :param x: vector of 32 bytes number serving as mask
    :param P1: public key 1, from_string format (32bytes)
    :param P2: public key 2, from_string format (32bytes)
    :param indices: vector of number (1 and 0 in our case) to specify which public key will be used to close the ring
    :return: a triplet consisting of L1: vector of public key (to_string format, 32bytes)
                                     s2: vector of 32 bytes number
                                     s: 32 bytes number, aggregate of s1
    """
    n = len(x)
    L1 = [None] * n
    s1 = [None] * n
    s2 = [None] * n
    s = to_32_bytes_number(0)
    print("------ Creating signature of the amount ------")
    for j in range(0, n):
        if j % (n // 10) == 0:
            print("------           [", end="")
            for u in range(0, 10):
                if u < (j * 10) / n:
                    print("#", end="")
                else:
                    print(" ", end="")
            print("]           ------")
        L1[j], s1[j], s2[j] = generate_schnorr_non_linkable(
            x[j], P1[j], P2[j], indices[j]
        )
        if debug:
            verify_schnorr_non_linkable(P1[j], P2[j], L1[j], s1[j], s2[j])
        s = add_2_32b(s, s1[j])
    return L1, s2, s


def verifiy_ASNL(P1, P2, L1, s2, s):
    """

    :param P1: public key 1, from_string format (32bytes)
    :param P2: public key 2, from_string format (32bytes)
    :param L1: vector of public key (to_string format, 32bytes)
    :param s2: vector of 32 bytes number
    :param s: 32 bytes number, aggregate of s1
    :return:
    """
    n = len(P1)
    LHS = to_32_bytes_number(0)
    RHS = g.from_string(s, curve=crv).verifying_key.pubkey.point
    for j in range(0, n):
        c2 = hashlib.sha256(L1[j]).digest()
        L2Point = g.from_string(s2[j], curve=crv).verifying_key.pubkey.point + (
            VerifyingKey.from_string(P2[j], curve=crv).pubkey.point
            * to_int_from_bytes(c2)
        )
        L2 = VerifyingKey.from_public_point(L2Point, curve=crv).to_string()
        if j == 0:
            LHS = VerifyingKey.from_string(L1[j], curve=crv).pubkey.point
        else:
            LHS = LHS + VerifyingKey.from_string(L1[j], curve=crv).pubkey.point
        c1 = hashlib.sha256(L2).digest()
        RHS = RHS + (
            VerifyingKey.from_string(P1[j], curve=crv).pubkey.point
            * to_int_from_bytes(c1)
        )
    assert (
        VerifyingKey.from_public_point(LHS, curve=crv).to_string()
        == VerifyingKey.from_public_point(RHS, curve=crv).to_string()
    ), "generate_ASNL failed to generate a valid signature.\nAborting..."


def prove_range_signatures(amount):
    """

    :param amount: the amount that should be proved (int)
    :return: a list made of C_pk: output commitment serving as a public key (to_string 32bytes format)
                            mask: part of the private key for C_pk. mask * G + amount * H == C_pk, 32 bytes number
                                  format
                            rg: vector of range proofs, each entry contain a vector of public key Ci and a
                                aggregate signature.
                            The aggregate signature itself contains L1: vector of public key (to_string format, 32bytes)
                                                                    s2: vector of 32 bytes number
                                                                    s: 32 bytes number, aggregate of s1
    For more info on asig, see generate_ASNL(...)
    """

    HPow2 = hash_to_point(to_32_bytes_number(1)).pubkey.point
    H2 = []
    for i in range(0, ATOMS):
        H2.append(VerifyingKey.from_public_point(HPow2, curve=crv).to_string())
        HPow2 = HPow2 * 2

    def d2b(n, digits):
        b = [0] * digits
        i = 0
        while n:
            b[i] = n & 1
            i = i + 1
            n >>= 1
        return b

    bb = d2b(amount, ATOMS)  # gives binary form of bb in "digits" binary digits
    mask = to_32_bytes_number(0)

    ai = []
    Ci = []
    CiH = []

    print("------   Preparing different elements   ------")
    for i in range(0, ATOMS):
        ai.append(to_32_bytes_number(random.randrange(crv.order)))
        mask = add_2_32b(
            mask, ai[i]
        )  # creating the total mask since you have to pass this to receiver...
        if bb[i] == 0:
            Ci.append(g.from_string(ai[i], curve=crv).verifying_key.to_string())
        if bb[i] == 1:
            Ci.append(
                VerifyingKey.from_public_point(
                    g.from_string(ai[i], curve=crv).verifying_key.pubkey.point
                    + VerifyingKey.from_string(H2[i], curve=crv).pubkey.point,
                    curve=crv,
                ).to_string()
            )

        negateH2 = Point(
            crv.curve,
            VerifyingKey.from_string(H2[i], curve=crv).pubkey.point.x(),
            (-VerifyingKey.from_string(H2[i], curve=crv).pubkey.point.y()),
            crv.order,
        )
        CiH.append(
            VerifyingKey.from_public_point(
                VerifyingKey.from_string(Ci[i], curve=crv).pubkey.point + negateH2,
                curve=crv,
            ).to_string()
        )

        if debug and bb[i] == 1:
            # Sanity check A + h2 - h2 == A
            assert (
                g.from_string(ai[i], curve=crv).verifying_key.to_string() == CiH[i]
            ), (
                "Sanity check failed in prove_range_signatures !"
                + bytes.hex(g.from_string(ai[i], curve=crv).verifying_key.to_string())
                + " ---- "
                + bytes.hex(CiH[i])
            )
    if rang_sig_bool:
        L1, s2, s = generate_ASNL(ai, Ci, CiH, bb)
        if debug:
            verifiy_ASNL(Ci, CiH, L1, s2, s)

        asig = [L1, s2, s]
        rg = [Ci, asig]
    else:
        rg = 1

    C_point = VerifyingKey.from_string(Ci[0], curve=crv).pubkey.point
    for i in range(1, len(Ci)):
        C_point = C_point + VerifyingKey.from_string(Ci[i], curve=crv).pubkey.point

    C = to_32_bytes_number(0)
    for i in range(0, len(Ci)):
        C = add_2_32b(C, Ci[i])

    C_pk = VerifyingKey.from_public_point(C_point, curve=crv)
    if debug:
        x = (
            hash_to_point(to_32_bytes_number(1)).pubkey.point * amount
            + g.from_string(mask, curve=crv).verifying_key.pubkey.point
        )
        assert (
            C_pk.to_string() == VerifyingKey.from_public_point(x, curve=crv).to_string()
        ), (
            "Something went wrong in the genreation of the commitment! "
            + bytes.hex(C_pk.to_string())
            + " should equal "
            + bytes.hex(VerifyingKey.from_public_point(x, curve=crv).to_string())
        )

    return C_pk.to_string(), mask, rg


def verify_range_proofs(rg):
    HPow2 = hash_to_point(to_32_bytes_number(1)).pubkey.point
    H2 = []
    for i in range(0, ATOMS):
        H2.append(VerifyingKey.from_public_point(HPow2, curve=crv).to_string())
        HPow2 = HPow2 * 2
    CiH = []
    Ci = rg[0]
    [L1, s2, s] = rg[1]
    for i in range(0, ATOMS):
        negate_h2 = Point(
            crv.curve,
            VerifyingKey.from_string(H2[i], curve=crv).pubkey.point.x(),
            (-VerifyingKey.from_string(H2[i], curve=crv).pubkey.point.y()),
            crv.order,
        )
        CiH.append(
            VerifyingKey.from_public_point(
                VerifyingKey.from_string(Ci[i], curve=crv).pubkey.point + negate_h2,
                curve=crv,
            ).to_string()
        )
    verifiy_ASNL(Ci, CiH, L1, s2, s)
