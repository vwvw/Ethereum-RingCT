var ringCT = artifacts.require("./online/ringCT.sol");
var RingSig = artifacts.require("./RingSig.sol");
module.exports = function(deployer) {
  deployer.deploy(RingSig);
  deployer.link(RingSig, ringCT);
  deployer.deploy(ringCT);
};
