// to run in geth: Secp256k1Curve


remixInterface = [{"constant":false,"inputs":[],"name":"testA","outputs":[],"payable":false,"type":"function"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_value","type":"uint256"}],"name":"PrintUint","type":"event"}]


remixData = "6060604052341561000c57fe5b5b6101c28061001c6000396000f30060606040526000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806371dd626b1461003b575bfe5b341561004357fe5b61004b61004d565b005b600060006000600060059350600090505b600281101561013e5782805480600101828161007a9190610145565b916000526020600020900160005b83909190915055507fa2a5950148bc9daaf224d9f6390a848d1fd96feecea86acf576f80ff2bb7829883805490506040518082815260200191505060405180910390a18180548060010182816100de9190610145565b916000526020600020900160005b6000909190915055507fa2a5950148bc9daaf224d9f6390a848d1fd96feecea86acf576f80ff2bb7829883805490506040518082815260200191505060405180910390a15b808060010191505061005e565b5b50505050565b81548183558181151161016c5781836000526020600020918201910161016b9190610171565b5b505050565b61019391905b8082111561018f576000816000905550600101610177565b5090565b905600a165627a7a72305820d257a2797ba4d7d1417a02098769761f935af095df2b58954af6116d85dbabba0029"





personal.unlockAccount(eth.accounts[0], "password", 50000000);
console.log("Unlocked account")

miner.start(1)
console.log("Started mining")

var ringct_sol_ringctContract = web3.eth.contract(remixInterface);

console.log("set contract")
var ringct_sol_ringct = ringct_sol_ringctContract.new(
   {
     from: web3.eth.accounts[0], 
     data: '0x' + remixData, 
     gas: '4700000'
   }, function (e, contract){
    console.log(e, contract);
    if (typeof contract.address !== 'undefined') {
         console.log('Contract mined! address: ' + contract.address + ' transactionHash: ' + contract.transactionHash);
         // var R = ringct_sol_ringct.R({_from: web3.eth.coinbase})
		// var logErrorStringEvent = ringct_sol_ringct.LogErrorString({_from: web3.eth.coinbase});
		// var printStringEvent = ringct_sol_ringct.PrintString({_from: web3.eth.coinbase});
		// var printBoolEvent = ringct_sol_ringct.PrintBool({_from: web3.eth.coinbase});
		// var printAddressEvent = ringct_sol_ringct.PrintAddress({_from: web3.eth.coinbase});
		var printUintEvent = ringct_sol_ringct.PrintUint({_from: web3.eth.coinbase});
		console.log("Listening on event")

		// R.watch(function(err, result) {
		//   if (err) {
		//     console.log(err)
		//     return;
		//   }
		//   console.log("res")
		//   console.log(JSON.stringify(result.args))
		// })
		// logErrorStringEvent.watch(function(err, result) {
		//   if (err) {
		//     console.log(err)
		//     return;
		//   }
		//   console.log(result.args._value)
		// })

		// printStringEvent.watch(function(err, result) {
		//   if (err) {
		//     console.log(err)
		//     return;
		//   }
		//   console.log(result.args._value)
		// })
		// printBoolEvent.watch(function(err, result) {
		//   if (err) {
		//     console.log(err)
		//     return;
		//   }
		//   console.log("boolean incoming: " + result.args._value)
		// })
		// printAddressEvent.watch(function(err, result) {
		//   if (err) {
		//     console.log(err)
		//     return;
		//   }
		//   console.log("address incoming: " +result.args._value)
		// })
		printUintEvent.watch(function(err, result) {
		  if (err) {
		    console.log(err)
		    return;
		  }
		  console.log("uint incoming: " + result.args._value)
		})

		console.log("sending transaction")
		x = ringct_sol_ringct.testA.sendTransaction("", {from: web3.eth.coinbase})
		// console.log(x)
		console.log("done transaction")
		//ringct_sol_ringct.test.sendTransaction('sendTransaction message', {from: web3.eth.coinbase})


    }
    setTimeout(function(){
		// miner.stop()
		console.log("Stoped mining")
	}, 45000);
 })

