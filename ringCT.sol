pragma solidity ^0.4.0;
contract RingCT {

    event PrintString(
        string _value
    );


    Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
    Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
    P = -4294968273
    ECADD = 5
    ECMUL = 6
    MODEXP = 7

    kimage[] memory keyImagesUsed = new kimage[];

    function verifyRing return boolean (bytes pubKeys, string m, bytes32 keyMatrix) {
        numberInput = keyMatrix.length;

        if(pubKeys.length != numberInput) {
            PrintString("the number of public keys and the size of the ring dont match")
            return false;
        }

        for(uint256 i = 1; i < numberInput; i++ {

        }
    }


    function verifyRangeProofs return boolean () {
    }

    function verify  (bytes keyImage, string m, bytes32 keyMatrix, bytes32 rangeProofs) returns (boolean){
        for(uint256 i = 0; i < keyImagesUsed.length; i++) {
            if(keyImagesUsed[i] == keyImage) {
                return false;
            }
        }
        if(!verifyRangeProofs(rangeProofs)) {
            return false;
        } 
        if(!verifyRing(keyImage, m, keyMatrix)) {
            return false;
        }
        keyImagesUsed.push(keyImage);


        /* inscribe the transaction in the block chain
         */
    }

}
