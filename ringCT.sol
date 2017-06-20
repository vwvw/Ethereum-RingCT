pragma solidity ^0.4.11;

import './Curve.sol';
import './ECCMath.sol';
import './Secp256k1Curve.sol';
import './Secp256k1.sol';

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
        uint256 ssX; 
        uint256 ssY;
        uint256[100] ss; // m x n matrix, scalar
        uint256 cc; // c1, scalar
        uint256 IIX;
        pubKey[100] II; // m x 1
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
    event PrintString(string _value);
    event PrintBool(bool _value);
    event PrintAddress(address _value);
    event PrintUint(uint256 _value);
    event PrintStringAndUint(string s, uint256 _value);

    // Base point (generator) G
    uint constant Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint constant Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    uint[2] GA = [Gx, Gy];
    pubKey G = pubKey(GA);
    int256 ECADD = 5;
    int256 ECMUL = 6;
    int256 MODEXP = 7;
    
    bytes32[] keyImagesUsed;

    function test(string tester, string t2, uint256 x, bytes32[2][] y) returns (string, string, uint256, bytes32[2][]) {
        LogErrorString("-------------------");
        PrintString("We got a nice message:");
        PrintString(tester);
    

        PrintString("-------------------");
        return (tester, t2, x, y);
    }

    function testb(string message, uint256 pkX, uint256 pkY, bytes32[2][] pkB, bytes32 c0, uint256 ssX, uint256 ssY, bytes32[] ssB, uint256 IIX, bytes32[2][] IIB) {
        
        if(pkX*pkY != pkB.length) {
           LogErrorString("Mismatch in the dimension of the key matrix");
        }
        PrintString(message);

        pubKey[100] memory II;
        for(uint i = 0; i < IIX; i++) {
            II[i] = pubKeyConverter(IIB[i]);
        }
        mgSig memory mg = mgSig(ssX, ssY, convertSS(ssB), uint256(c0), IIX, II);
        // PrintUint(mg.cc);
        PrintBool(verifyMLSAG(message, pkX, pkY, convertPK(pkB), mg));
    }

    function convertPK(bytes32[2][] pkB) internal returns (pubKey[100]) {
        // assert(pkB.length) < 100);
        pubKey[100] memory pk;
        for(uint i = 0; i < pkB.length; i++) {
            pk[i] = pubKeyConverter(pkB[i]);
        }
        return pk;
    }

    function convertSS(bytes32[] ssB) internal returns (uint256[100]) {
        // assert(ssB.length) < 100);
        uint256[100] memory ss;
        for(uint i = 0; i < ssB.length; i++) {
            ss[i] = uint(ssB[i]);
        }
        return ss;
    }

    function pubKeyConverter(bytes32[2] p) internal returns (pubKey) {
        uint256 x = uint256(p[0]);
        uint256 y = uint256(p[1]);
        uint256[2] memory pp = [x, y];
        return pubKey(pp);
    }

    function verifyMLSAG(string messageString, uint256 pkX, uint256 pkY, pubKey[100] km, mgSig mg) internal returns (bool) {
        // VER: A polynomial time algorithm which takes as inputs 
        // a security parameter k,
        // a key matrix km, 
        // a message m, 
        // and a signature σ on km, m, 
        // and outputs true or false, depending on whether the signature verifies or not. 
        // For completeness, the MLSAG scheme must satisfy VER(SIGN(m,L,x),m,L)=true with overwhelming probability at security level k.
        // PrintStringAndUint("hello", 12);
        if(mg.ssX != pkX) {
            LogErrorString("Mismatch in the dimension of the key matrix and the ss matrix in the signature");
            PrintStringAndUint("pkX:", pkX);
            PrintStringAndUint("ssX:", mg.ssX);
        }
        if (mg.ssY != pkY) {
            PrintBool(mg.ssY != pkY);
            LogErrorString("2Mismatch in the dimension of the key matrix and the ss matrix in the signature");
            PrintUint(pkY);
            PrintUint(mg.ssY);
            PrintStringAndUint("pkY:", pkY);
            PrintStringAndUint("ssY:", mg.ssY);
            PrintUint(pkY);
            PrintUint(mg.ssY);
        }
        if(mg.ssY != mg.IIX) {
            LogErrorString("Mismatch in the dimension of the II matrix and the ss matrix in the signature");
        }
        uint256 m = mg.ssX;
        uint256 n = mg.ssY;
        uint256[] memory c = new uint256[](n+1);
        c[0] = (mg.cc);
        for(uint256 i = 1; i < n; i++) {
            c[i] = (calculateC(messageString, [m, i, c[i-1]], km, mg));
        }
        // return true;
        c[n] = (calculateC(messageString, [m, 0, c[n-1]], km, mg));
        return c[0] == c[c.length-1];
    }

    function calculateC (string messageString, uint256[3] restOfStuff, pubKey[100] km, mgSig mg) internal returns (uint256) {
        // restOfStuff [m, i, cBefore]
        uint256[3][] memory L = new uint256[3][](restOfStuff[0]);
        uint256[3][] memory R = new uint256[3][](restOfStuff[0]);
        for(uint256 j = 0; j < restOfStuff[0]; j++) {
            L[j] = (ecadd(L1(j, restOfStuff, mg), L2(j, restOfStuff, km)));
            R[j] = (ecadd(R1(j, restOfStuff, km, mg), R2(j, restOfStuff, mg)));
        }
        // return uint256(sha3(messageString));
        return uint256(sha3(messageString, L, R));
    }

    function L1 (uint256 j, uint256[3] restOfStuff, mgSig mg) internal returns (uint256[3] ) {
        return ecmul(mg.ss[restOfStuff[1] * restOfStuff[0] + j], G.key);
    }

    function L2 (uint256 j, uint256[3] restOfStuff, pubKey[100] km) internal returns (uint256[3]) {
        return ecmul(restOfStuff[2], km[restOfStuff[1] * restOfStuff[0] + j].key);
    }

    function R1 (uint256 j, uint256[3] restOfStuff, pubKey[100] km, mgSig mg) internal returns (uint256[3]) {
        uint256 A = mg.ss[restOfStuff[1] * restOfStuff[0] + j];
        uint256[2] memory B = [uint(sha3(km[restOfStuff[1] * restOfStuff[0] + j].key[0])), uint(sha3(km[restOfStuff[1] * restOfStuff[0] + j].key[1]))];
        return ecmul(A, B);
    }

    function R2 (uint256 j, uint256[3] restOfStuff, mgSig mg) internal returns (uint256[3]) {
        return ecmul(restOfStuff[2], mg.II[j].key);
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


    // function verifyRangeProofs (rangeSig rp, pubKey commitment) internal returns (bool result) {
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
    // }

    // function verifyBoromean (rangeSig rp) internal returns (bool result) {

    // }


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









    uint256 constant a=0;
    uint256 constant b=7;
    uint256 constant p=115792089237316195423570985008687907853269984665640564039457584007908834671663;
    uint256 constant n=115792089237316195423570985008687907852837564279074904382605163141518161494337;
    uint256 constant gx=55066263022277343669578718895168534326250603453777594175500187360389116729240;
    uint256 constant gy=32670510020758816978083085130507043184471273380659243275938904335757337482424;
    

      //Helper functions from ECMath.sol
    // point addition for elliptic curve in jacobian coordinates
    // formula from https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates
    function ecadd(uint256[3] P, uint256[3] Q)  returns (uint256[3] R) {

        uint256 u1;
        uint256 u2;
        uint256 s1;
        uint256 s2;

        if (Q[0]==0 && Q[1]==0 && Q[2]==0) {
            return P;
        }

        u1 = mulmod(P[0],mulmod(Q[2],Q[2],p),p);
        u2 = mulmod(Q[0],mulmod(P[2],P[2],p),p);
        s1 = mulmod(P[1],mulmod(mulmod(Q[2],Q[2],p),Q[2],p),p);
        s2 = mulmod(Q[1],mulmod(mulmod(P[2],P[2],p),P[2],p),p);

        if (u1==u2) {
            if (s1 != s2) {
                R[0]=1;
                R[1]=1;
                R[2]=0;
                return R;
            }
            else {
                return ecdouble(P);
            }
        }

        uint256 h;
        uint256 r;
    
        h = addmod(u2,(p-u1),p);
        r = addmod(s2,(p-s1),p);
    
        R[0] = addmod(addmod(mulmod(r,r,p),(p-mulmod(h,mulmod(h,h,p),p)),p),(p-mulmod(2,mulmod(u1,mulmod(h,h,p),p),p)),p);
        R[1] = addmod(mulmod(r,addmod(mulmod(u1,mulmod(h,h,p),p),(p-R[0]),p),p),(p-mulmod(s1,mulmod(h,mulmod(h,h,p),p),p)),p);
        R[2] = mulmod(h,mulmod(P[2],Q[2],p),p);
    
        return (R);
    }

    //point doubling for elliptic curve in jacobian coordinates
    //formula from https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates
    function ecdouble(uint256[3] P) private constant returns(uint256[3] R){
    
        //return point at infinity
        if (P[1]==0) {
            R[0]=1;
            R[1]=1;
            R[2]=0;
            return (R);
        }
    
        uint256 m;
        uint256 s;
    
        s = mulmod(4,mulmod(P[0],mulmod(P[1],P[1],p),p),p);
        m = addmod(mulmod(3,mulmod(P[0],P[0],p),p),mulmod(a,mulmod(mulmod(P[2],P[2],p),mulmod(P[2],P[2],p),p),p),p);
        R[0] = addmod(mulmod(m,m,p),(p-mulmod(s,2,p)),p);
        R[1] = addmod(mulmod(m,addmod(s,(p-R[0]),p),p),(p-mulmod(8,mulmod(mulmod(P[1],P[1],p),mulmod(P[1],P[1],p),p),p)),p);
        R[2] = mulmod(2,mulmod(P[1],P[2],p),p);
    
        return (R);
    }


    // function for elliptic curve multiplication in jacobian coordinates using Double-and-add method
    function ecmul(uint256 d, uint256[2] P_tmp) returns(uint256[3] R) {

        uint256[3] P;
        P[0]=P_tmp[0];
        P[1]=P_tmp[1];
        P[2]=1;

        R[0]=0;
        R[1]=0;
        R[2]=0;
    
        //return (0,0) if d=0 or (x1,y1)=(0,0)
        if (d == 0 || ((P[0]==0) && (P[1]==0)) ) {
            return (R);
        }
        uint256[3] memory T;
        T[0]=P[0]; //x-coordinate temp
        T[1]=P[1]; //y-coordinate temp
        T[2]=P[2]; //z-coordiante temp
    
        while (d != 0) {
            if ((d & 1) == 1) {  //if last bit is 1 add T to result
                R = ecadd(T,R);
            }
            T = ecdouble(T);    //double temporary coordinates
            d=d/2;              //"cut off" last bit
        }
        return R;
    }

}
