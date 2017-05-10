pragma solidity ^0.4.0;

import 'github.com/androlo/standard-contracts/contracts/src/crypto/Curve.sol';


contract RingCT {

    event PrintString(address indexed _from, string _value);


    int256 Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240;
    int256 Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424;
    int256 P = -4294968273;
    int256 ECADD = 5;
    int256 ECMUL = 6;
    int256 MODEXP = 7;
    
    bytes32[] keyImagesUsed;

    function test(string tester) {
        PrintString(msg.sender, "-------------------");
        PrintString(msg.sender, "We got a message:");
        PrintString(msg.sender, tester);
        PrintString(msg.sender, "-------------------");
        // Curve x = Curve(2);
        //uint[2] y= [1,2];
        // x.onCurve(y);
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
