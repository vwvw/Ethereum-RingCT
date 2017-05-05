pragma solidity ^0.4.0;
contract RingCT {


    Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
    Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
    P = -4294968273
    ECADD = 5
    ECMUL = 6
    MODEXP = 7

    kimage[] memory keyImagesUsed = new kimage[];

    function verifyRing return boolean (bytes keyImage, string m, bytes32 keyMatrix) {

    }


    function verifyRangeProofs return boolean () {
    }

    function verify  (bytes keyImage, string m, bytes32 keyMatrix, bytes32 rangeProofs) returns (boolean){
        for(uint256 i = 0; i < keyImagesUsed.lenngth; i++) {
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
    }

}
