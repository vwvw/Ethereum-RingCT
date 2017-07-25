 pragma solidity ^0.4.11;


contract RingCT {




    struct pubKey {
        uint256[2] key;
    }
    
    struct boroSig {
        bytes32[64] s0;
        bytes32[64] s1;
        bytes32 ee;
    }
    
    //just contains the necessary keys to represent MLSAG. sigs
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
        bytes32[64] s0;
        bytes32[64] s1;
        bytes32 ee;
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
    uint256 constant Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 constant Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 ATOMS = 64;
    uint256[2] GA = [Gx, Gy];
    pubKey G = pubKey(GA);
    int256 ECADD = 5;
    int256 ECMUL = 6;
    int256 MODEXP = 7;
    
    bytes32[] keyImagesUsed;

    function test(uint256 i) {
        LogErrorString("-------------------");
        PrintString("We got a nice message:");
    

        PrintString("-------------------");
    }

    function y () {
        PrintUint(uint256(1));
        // PrintUint(JtoA(ecmul(uint256(71449910333075107539383320123832160761226081732216163042225240336241879234277), G.key))[1]);
        
    }
    // def verTransaction(message, newMatrix, I, c_0, ss, infos, rangeSig):
    function verify(string message, string infos, uint256[2] pkDim, bytes32[2][] pkB, bytes32 c0, uint256[2] ssDim, bytes32[] ssB, uint256 IIX, bytes32[2][] IIB, uint256[2] Cdim, uint256[2][] CiArray, uint256[2][] L1Array, uint256[] s2Array, uint256[] sArray) {
        // verifySignature(string message, pkDim[0], pkDim[1], pkB, c0, ssDim[0], ssDim[1], ssB, IIX, IIB);
        verifyRangeProofs(Cdim[0], Cdim[1], CiArray, L1Array, s2Array, sArray);
    }

    function verifyRangeProofs(uint256 Cx, uint256 Cy, uint256[2][] CiArray, uint256[2][] L1Array, uint256[] s2Array, uint256[] sArray) {
        uint256 n = sArray.length; //number of range verRangeProofs
        if(Cx != n) {
           LogErrorString("Mismatch in the dimension of the Ci matrix and other matrixes");
           return;
        }
        if(Cx * Cy != CiArray.length) {
           LogErrorString("Mismatch in the dimension of the Ci matrix");
           return;
        }
        for(uint256 i = 0; i < n; i++) {
            uint256[2][] memory Ci = new uint256[2][](Cy);
            uint256[2][] memory L1 = new uint256[2][](Cy);
            uint256[] memory s2 = new uint256[](Cy);
            for(uint256 j = 0; j < Cy; j++) {
                Ci[j] = CiArray[i * Cy + j];
                L1[j] = L1Array[i * Cy + j];
                s2[j] = s2Array[i * Cy + j];
            }
            // function verRangeProofs(uint256[2][] Ci, uint256[2][] L1, uint256[] s2, uint256 s) {
            // verRangveProofs(Ci, L1, s2, sArray[i]);
        }
    }

    function verifySignature(string message, uint256 pkX, uint256 pkY, bytes32[2][] pkB, bytes32 c0, uint256 ssX, uint256 ssY, bytes32[] ssB, uint256 IIX, bytes32[2][] IIB) {
        
        if(pkX*pkY != pkB.length) {
           LogErrorString("Mismatch in the dimension of the key matrix");
           return;
        }
        PrintString(message);

        pubKey[100] memory II;
        for(uint256 i = 0; i < IIX; i++) {
            II[i] = pubKeyConverter(IIB[i]);
        }
        mgSig memory mg = mgSig(ssX, ssY, convertSS(ssB), uint256(c0), IIX, II);
        // PrintUint(1);
        PrintBool(verifyMLSAG(message, pkX, pkY, convertPK(pkB), mg));
    }

    function convertPK(bytes32[2][] pkB) internal returns (pubKey[100]) {
        // assert(pkB.length) < 100);
        pubKey[100] memory pk;
        for(uint256 i = 0; i < pkB.length; i++) {
            pk[i] = pubKeyConverter(pkB[i]);
        }
        return pk;
    }

    function convertSS(bytes32[] ssB) internal returns (uint256[100]) {
        // assert(ssB.length) < 100);
        uint256[100] memory ss;
        for(uint256 i = 0; i < ssB.length; i++) {
            ss[i] = uint256(ssB[i]);
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
        if(mg.ssX != pkX || mg.ssY != pkY) {
            LogErrorString("Mismatch in the dimension of the key matrix and the ss matrix in the signature");
        }
        if(mg.ssY != mg.IIX) {
            LogErrorString("Mismatch in the dimension of the II matrix and the ss matrix in the signature");
        }
        uint256 n = mg.ssX;
        uint256 m = mg.ssY;
        uint256[] memory c = new uint256[](n);
        c[n - 1] = mg.cc;
        // PrintUint(mg.cc);
        // PrintUint(c[n-1]);
        // PrintUint(n-1);
        // PrintUint((i-1)%(n+1));
        // PrintUint(c[(i-1)%(n)]);
        // PrintUint(333333333);
        for(uint256 i = 0; i < n; i++) {
          c[i] = calculateC(messageString, [m, i, c[(i+n-1)%(n)]], km, mg);
        }
        // return true;
        return mg.cc == c[c.length-1];
    }

    function calculateC (string messageString, uint256[3] restOfStuff, pubKey[100] km, mgSig mg) internal returns (uint256 c) {
        // restOfStuff [m, i, cBefore]
        uint256[2][] memory L = new uint256[2][](restOfStuff[0]);
        uint256[2][] memory R = new uint256[2][](restOfStuff[0]);
        for(uint256 j = 0; j < restOfStuff[0]; j++) {
            L[j] = JtoA(ecadd(L1(j, restOfStuff, mg), L2(j, restOfStuff, km)));
            // PrintUint(L[j][0]);
            // PrintUint(L[j][1]);
            // PrintUint(uint256(1111111111111111));
            R[j] = JtoA(ecadd(R1(j, restOfStuff, km, mg), R2(j, restOfStuff, mg)));
            // PrintUint(R[j][0]);
            // PrintUint(R[j][1]);
            // PrintUint(uint256(2222222222222222));
        }
        // return uint256(sha3(messageString));
        c =  uint256(sha3(messageString, L, R));
        // PrintUint(8888888);
        // PrintUint(c);
        // PrintUint(8888888);
        return c;
    }

    function L1 (uint256 j, uint256[3] restOfStuff, mgSig mg) internal returns (uint256[3] res) {
        GA = [Gx, Gy];
        G = pubKey(GA);
        res = ecmul(mg.ss[restOfStuff[1] * restOfStuff[0] + j], G.key);
        // PrintUint(3333333);
        // PrintUint(JtoA(res)[0]);
        // PrintUint(JtoA(res)[1]);
        // PrintUint(3333333);
        return res;
    }

    function L2 (uint256 j, uint256[3] restOfStuff, pubKey[100] km) internal returns (uint256[3] res) {
        res =  ecmul(restOfStuff[2], km[restOfStuff[1] * restOfStuff[0] + j].key);
        // PrintUint(4444444);
        // PrintUint(JtoA(res)[0]);
        // PrintUint(JtoA(res)[1]);
        // PrintUint(4444444);
        return res;
    }

    function R1 (uint256 j, uint256[3] restOfStuff, pubKey[100] km, mgSig mg) internal returns (uint256[3] res) {
        uint256 A = mg.ss[restOfStuff[1] * restOfStuff[0] + j];
        uint256 B = uint(sha256(km[restOfStuff[1] * restOfStuff[0] + j].key));
        GA = [Gx, Gy];
        G = pubKey(GA);
        uint256[2] memory C = JtoA(ecmul(B, G.key));
        res = ecmul(A, C);
        // PrintUint(5555555);
        // PrintUint(JtoA(res)[0]);
        // PrintUint(JtoA(res)[1]);
        // PrintUint(5555555);
        return res;
    }

    function R2 (uint256 j, uint256[3] restOfStuff, mgSig mg) internal returns (uint256[3] res) {
        res = ecmul(restOfStuff[2], mg.II[j].key);
        // PrintUint(6666666);
        // PrintUint(JtoA(res)[0]);
        // PrintUint(JtoA(res)[1]);
        // PrintUint(6666666);
        return res;
    }

    uint256 constant a=0;
    uint256 constant b=7;
    uint256 constant p=115792089237316195423570985008687907853269984665640564039457584007908834671663;
    uint256 constant n=115792089237316195423570985008687907852837564279074904382605163141518161494337;
    uint256 constant gx=55066263022277343669578718895168534326250603453777594175500187360389116729240;
    uint256 constant gy=32670510020758816978083085130507043184471273380659243275938904335757337482424;
    

    function VerSchnorrNonLinkable(uint256[2] P1, uint256[2] P2, uint256[2] L1, bytes32 s1, bytes32 s2) {
        uint256 c2 = uint256(sha256(L1));
        uint256[3] memory x = ecmul(c2, P2);
        uint256[2] memory L2 = JtoA(ecadd(ecmul(uint256(s2), [gx,gy]), x));
        uint256 c1 = uint256(sha256(L2));
        uint256[2] memory L1p = JtoA(ecadd(ecmul(uint256(s1), [gx,gy]), ecmul(c1, P1)));
        PrintBool(L1p[0] == L1[0] && L1p[1] == L1[1]);
        PrintUint(L2[0]);
        PrintUint(L2[1]);
        PrintUint(L1p[0]);
        PrintUint(L1p[1]);
        PrintUint(L1[0]);
        PrintUint(L1[1]);
    }

    function VerASNL(uint256 P1x, uint256[2][] P1, uint256[2][] P2, uint256[2][] L1, uint256[] s2, uint256 s) {
        uint256[3] memory LHS = [uint256(0),0,0];
        uint256[3] memory RHS = ecmul(s, [gx, gy]);
        // PrintUint(JtoA(RHS)[0]);
        for(uint256 j = 0; j < P1x; j++) {
            uint256[6] memory LHRS = VerASNLHelper(j, L1[j], P1[j], P2[j], s2[j], LHS, RHS);
            LHS[0] = LHRS[0];
            LHS[1] = LHRS[1];
            LHS[2] = LHRS[2];
            RHS[0] = LHRS[3];
            RHS[1] = LHRS[4];
            RHS[2] = LHRS[5];
        }
        // PrintUint(JtoA(LHS)[0]);
        // PrintUint(JtoA(RHS)[0]);
        // PrintUint(JtoA(LHS)[1]);
        // PrintUint(JtoA(RHS)[1]);
        PrintBool(JtoA(RHS)[0] == JtoA(LHS)[0] && JtoA(RHS)[1] == JtoA(LHS)[1]);
    }

    function VerASNLHelper(uint256 j, uint256[2] L1j, uint256[2] P1j, uint256[2] P2j, uint256 s2j, uint256[3] LHS, uint256[3] RHS) returns (uint256[6] LRHS) {
        uint256 c2 = uint256(sha256(L1j));
        // PrintUint(c2);
        uint256[3] memory L2 = ecadd(ecmul(s2j, [gx, gy]), ecmul(c2, P2j));
        // PrintUint(JtoA(L2)[0]);
        uint256[3] memory LHS2 = [uint256(0), 0,0];
        if(j == uint256(0)) {
            LHS2 = ecmul(1, L1j);
        }
        else {
            LHS2 = ecadd(LHS, ecmul(1, L1j));
        }
        uint256 c1 = uint256(sha256(JtoA(L2)));
        // PrintUint(c1);
        uint256[3] memory RHS2 = ecadd(RHS, ecmul(c1, P1j));
        LRHS[0] = LHS2[0];
        LRHS[1] = LHS2[1];
        LRHS[2] = LHS2[2];
        LRHS[3] = RHS2[0];
        LRHS[4] = RHS2[1];
        LRHS[5] = RHS2[2];
    }

    function verRangeProofs(uint256[2][] Ci, uint256[2][] L1, uint256[] s2, uint256 s) {
        uint256[3] memory HPow2 = ecmul(uint256(sha256(1)), [gx, gy]);
        uint256[3][] memory H2 = new uint256[3][](ATOMS);
        for(uint256 i = 0; i < ATOMS; i++) {
            H2[i] = HPow2; 
            uint256[3] memory tmp = ecdouble(HPow2);
            HPow2 = tmp;
        }
        
        uint256[2][] memory CiH = new uint256[2][](ATOMS);
        for(i = 0; i < ATOMS; i++) {
            uint256[3] memory negateH2 = ecmul(uint256(-1), JtoA(H2[i]));
            CiH[i] = JtoA(ecadd(ecmul(1, Ci[i]), negateH2));
        }
        uint256 P1x = Ci.length;
        VerASNL(P1x, Ci, CiH, L1, s2, s);
}




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

    function invmod(uint256 a, uint p) private constant returns(uint256 invA) {
        uint256 t=0;
        uint256 newT=1;
        uint256 r=p;
        uint256 newR=a;
        uint256 q;
        while (newR != 0) {
          q = r / newR;

          (t, newT) = (newT, addmod(t , (p - mulmod(q, newT,p)) , p));
          (r, newR) = (newR, r - q * newR );
        }
        return t;
    }


   function JtoA(uint256[3] P) private constant returns (uint256[2] Pnew) {
        uint zInv = invmod(P[2],p);
        uint zInv2 = mulmod(zInv, zInv, p);
        Pnew[0] = mulmod(P[0], zInv2, p);
        Pnew[1] = mulmod(P[1], mulmod(zInv,zInv2,p), p);
    }


}
