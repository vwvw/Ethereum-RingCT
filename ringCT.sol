pragma solidity ^0.4.0;

import 'github.com/androlo/standard-contracts/contracts/src/crypto/Curve.sol';
import 'github.com/androlo/standard-contracts/contracts/src/crypto/ECCMath.sol';
import 'github.com/androlo/standard-contracts/contracts/src/crypto/Secp256k1Curve.sol';
import 'github.com/androlo/standard-contracts/contracts/src/crypto/Secp256k1.sol';

contract RingCT {
    struct pubKey {
        uint256[2] key;
    }
    
    struct boroSig {
        bytes32[64] s0;
        bytes32[64] s1;
        bytes32 ee;
    }
    
    //just contains the necessary keys to represent MLSAG sigs
    //c.f. http://eprint.iacr.org/2015/1098
    struct mgSig {
        uint256[][] ss; // m x n matrix, scalar
        uint256 cc; // c1, scalar
        pubKey[] II; // m x 1
    }
    
    struct rangeSig {
        boroSig asig;
        bytes32[64] Ci;
    }

    struct Ring {
        mgSig[] MGs; // simple rct has N, full has 1
        rangeSig[] RGs;
    }



    event LogErrorString(string _value);
    event PrintString(address indexed _from, string _value);
    event PrintBool(address indexed _from, bool _value);
    event PrintAddress(address indexed _from, address _value);
    event PrintUint(address indexed _from, uint _value);


    uint Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240;
    uint Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424;
    uint[2] GA = [Gx, Gy];
    pubKey G = pubKey(GA);
    int256 P = -4294968273;
    int256 ECADD = 5;
    int256 ECMUL = 6;
    int256 MODEXP = 7;
    
    bytes32[] keyImagesUsed;

    function test(string tester) returns (string) {
        LogErrorString("-------------------");
        PrintString(msg.sender, "We got a nice message:");
        PrintString(msg.sender, tester);
    
        uint q = 51096430820870120307140539508814444545925245321148382543282986788786670374103;
        uint w = 109585886259781532459003731753652036451736271709659651557868302973050866903014;
        
        bytes32 q2 = 0x70f78e12ca19e7ad5149e9e7aac89d472eba3eafda6dbd485d3c142e915b8cd7;
        bytes32 w2 = 0xf24769e16ee2286f4bbe6f7f7d881a012cce9a00a914c8ec5d3fb8f645a027e7;
        

        uint256[2] memory y = [q, w];
        pubKey memory h1 = pubKey(y);
        bool re = Secp256k1.onCurve(h1.key);
        PrintBool(msg.sender, re);

        uint r = ECCMath.invmod(q,w);
        PrintUint(msg.sender, uint(q2));
        PrintString(msg.sender, "-------------------");
        return tester;
    }

    function testb(uint256 x, uint256 y, bytes32[2][] t) returns (bytes32) {
//        if(x*y != t.length) {
  //          LogErrorString("Mismatch in the dimension of the key matrix");
    //    }
        PrintString(msg.sender, "We got a nice message:");
        pubKey[][] pk;
        bytes32[2][] o;
        for(uint i = 0; i < x; i++) {
            for(uint j = 0; j < y; j++) {
                o[i*y+j] = t[i*y+j];
                pk[i][j] = helper(t[i*y+j]);
            }
        }
        uint256[2] r = pk[0][0].key;
        return bytes32(pk[0][0].key[0]);
    }

    function helper(bytes32[2] p) internal returns (pubKey) {
        uint256 x = uint256(p[0]);
        uint256 y = uint256(p[1]);
        uint256[2] memory pp = [x, y];
        return pubKey(pp);

    }

    function verifyMLSAG(bytes32 messageString, pubKey[][] km, mgSig mg) internal returns (bool) {
        // VER: A polynomial time algorithm which takes as inputs 
        // a security parameter k,
        // a key matrix km, 
        // a message m, 
        // and a signature σ on km, m, 
        // and outputs true or false, depending on whether the signature verifies or not. 
        // For completeness, the MLSAG scheme must satisfy VER(SIGN(m,L,x),m,L)=true with overwhelming probability at security level k.

        // if(mg.ss.length != km.length || mg.ss[0].length != km[0].length) {
        //     LogErrorString("Mismatch in the dimension of the key matrix and the ss matrix in the signature");
        // }
        // if(mg.ss.length != mg.II.length) {
        //     LogErrorString("Mismatch in the dimension of the II matrix and the ss matrix in the signature");
        // }

        // uint m = mg.ss.length;
        // uint n = mg.ss[0].length;
        // uint[] c;
        // c.push(mg.cc);
        // for(uint i = 0; i < n; i++) {
        //     uint[3][] L;
        //     uint[3][] R;
        //     for(uint j = 0; j < m; j++) {
        //         L.push(Secp256k1._add(Secp256k1._mul(mg.ss[i][j], G.key), Secp256k1._mul(c[i], km[i][j].key)));
        //         R.push(Secp256k1._add(Secp256k1._mul(mg.ss[i][j], [uint(sha3(km[i][j].key[0])), uint(sha3(km[i][j].key[1]))]), Secp256k1._mul(c[i], mg.II[i].key)));
        //     }
        //     c.push(uint(sha256(messageString, L, R)));
        // }


        // return c[0] == c[c.length];
    }

    // function verifyRing (Ring r) returns (bool) {
    //     if(r.outPk.length != r.p.rangeSigs.length) {PrintString("Mismatched sizes of outPk and r.rangeSigs");};
    //     if(r.outPk.length == r.ecdhInfo.length) {PrintString("Mismatched sizes of outPk and r.ecdhInfo")};
    //     if(r.pseudoOuts.length == r.MGs.length) {PrintString("Mismatched sizes of r.pseudoOuts and r.MGs")};


    //     uint threads;
    //     if(r.outPk.length >r.mixRing.length {
    //         threads = r.outPk.length;
    //     } else {
    //         threads = r.mixRing.length;
    //     }

    //     bool[threads] results;

    //     bytes32 sumOutpks = 0x0100000000000000000000000000000000000000000000000000000000000000;
    //     for (uint i = 0; i < r.outPk.length; i++) {
    //         addKeys(sumOutpks, sumOutpks, rv.outPk[i].mask);
    //     }
    //     DP(sumOutpks);
    //     key txnFeeKey = scalarmultH(d2h(rv.txnFee));
    //     addKeys(sumOutpks, txnFeeKey, sumOutpks);

    //     bytes32 sumPseudoOuts = 0x0100000000000000000000000000000000000000000000000000000000000000;
    //     for (uint i = 0 ; i < rv.pseudoOuts.size() ; i++) {
    //         addKeys(sumPseudoOuts, sumPseudoOuts, rv.pseudoOuts[i]);
    //     }
    //     DP(sumPseudoOuts);

    //     //check pseudoOuts vs Outs..
    //     if (!equalKeys(sumPseudoOuts, sumOutpks)) {
    //         LOG_PRINT_L1("Sum check failed");
    //         return false;
    //     }

    //     results.clear();
    //     results.resize(rv.outPk.size());
    //     tools::task_region(threadpool, [&] (tools::task_region_handle& region) {
    //     for (size_t i = 0; i < rv.outPk.size(); i++) {
    //         region.run([&, i] {
    //             results[i] = verRange(rv.outPk[i].mask, rv.p.rangeSigs[i]);
    //         });
    //     }
    //     });

    //     for (size_t i = 0; i < results.size(); ++i) {
    //         if (!results[i]) {
    //             LOG_PRINT_L1("Range proof verified failed for output " << i);
    //             return false;
    //         }
    //     }
    // }


    function verifyRangeProofs (rangeSig rp, pubKey commitment) internal returns (bool result) {
        // uint[3] Ctmp;
        // Ctmp[0] = 0;
        // Ctmp[1] = 0;
        // Ctmp[2] = 0;

        // for(uint i = 0; i < 64; i++) {
        //     Ctmp = Secp256k1._addMixed(Ctmp, rp.Ci[i].key);
        // }
        // ECCMath.toZ1(Ctmp, pp); // to Jacobian 
        // if(Ctmp[0] != commitment.key[0] || Ctmp[1] != commitment.key[1]) {
        //     result = false;
        //     return;
        // } else {
        //     result = verifyBoromean(rp);
        //     return;
        // }
    }

    function verifyBoromean (rangeSig rp) internal returns (bool result) {

    }


    // function verify  (bytes32 keyImage, bytes pubKeys, string m, bytes32 keyMatrix, bytes32 rangeProofs) returns (bool){
    //     for(uint256 i = 0; i < keyImagesUsed.length; i++) {
    //         if(keyImagesUsed[i] == keyImage) {
    //             return false;
    //         }
    //     }
    //     if(!verifyRangeProofs(rangeProofs)) {
    //         return false;
    //     } 
    //     if(!verifyRing(pubKeys, m, keyMatrix)) {
    //         return false;
    //     }
    //     keyImagesUsed.push(keyImage);


    //     /* inscribe the transaction in the block chain
    //      */
    // }

}
