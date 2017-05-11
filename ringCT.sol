pragma solidity ^0.4.0;

import 'github.com/androlo/standard-contracts/contracts/src/crypto/Curve.sol';
import 'github.com/androlo/standard-contracts/contracts/src/crypto/ECCMath.sol';
import 'github.com/androlo/standard-contracts/contracts/src/crypto/Secp256k1Curve.sol';
import 'github.com/androlo/standard-contracts/contracts/src/crypto/Secp256k1.sol';

contract RingCT {

    event PrintString(address indexed _from, string _value);
    event PrintBool(address indexed _from, bool _value);
    event PrintAddress(address indexed _from, address _value);
    event PrintUint(address indexed _from, uint _value);


    int256 Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240;
    int256 Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424;
    int256 P = -4294968273;
    int256 ECADD = 5;
    int256 ECMUL = 6;
    int256 MODEXP = 7;
    
    bytes32[] keyImagesUsed;

    function test(string tester) returns (bool) {
        PrintString(msg.sender, "-------------------");
        PrintString(msg.sender, "We got a nice message:");
        PrintString(msg.sender, tester);
    
        uint q = 1;
        uint w = 2;
        uint[2] memory y = [q, w];
        bool re = Secp256k1.onCurve(y);
        PrintBool(msg.sender, re);

        uint r = ECCMath.invmod(q,w);
        PrintUint(msg.sender, r);
        PrintString(msg.sender, "-------------------");
    }



    function verifyRing (bytes pubKeys, string m, bytes32 keyMatrix) returns (bool) {
        uint256 numberInput = keyMatrix.length;
        

        if(pubKeys.length != numberInput) {

            return false;
        }

        for(uint256 i = 1; i < numberInput; i++) {

        }
    }


    function verifyRangeProofs (bytes32 rangeProofs) returns (bool) {
    }

    function verify  (bytes32 keyImage, bytes pubKeys, string m, bytes32 keyMatrix, bytes32 rangeProofs) returns (bool){
        for(uint256 i = 0; i < keyImagesUsed.length; i++) {
            if(keyImagesUsed[i] == keyImage) {
                return false;
            }
        }
        if(!verifyRangeProofs(rangeProofs)) {
            return false;
        } 
        if(!verifyRing(pubKeys, m, keyMatrix)) {
            return false;
        }
        keyImagesUsed.push(keyImage);


        /* inscribe the transaction in the block chain
         */
    }

}
