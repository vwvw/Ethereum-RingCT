// to run in geth: Secp256k1Curve


remixInterface = [{"constant":false,"inputs":[{"name":"tester","type":"string"},{"name":"t2","type":"string"},{"name":"x","type":"uint256"},{"name":"y","type":"bytes32[2][]"}],"name":"test","outputs":[{"name":"","type":"string"},{"name":"","type":"string"},{"name":"","type":"uint256"},{"name":"","type":"bytes32[2][]"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"message","type":"string"},{"name":"pkX","type":"uint256"},{"name":"pkY","type":"uint256"},{"name":"pkB","type":"bytes32[2][]"},{"name":"c0","type":"bytes32"},{"name":"ssX","type":"uint256"},{"name":"ssY","type":"uint256"},{"name":"ssB","type":"bytes32[]"},{"name":"IIX","type":"uint256"},{"name":"IIB","type":"bytes32[2][]"}],"name":"testb","outputs":[],"payable":false,"type":"function"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_value","type":"string"}],"name":"LogErrorString","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_value","type":"string"}],"name":"PrintString","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_value","type":"bool"}],"name":"PrintBool","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_value","type":"address"}],"name":"PrintAddress","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_value","type":"uint256"}],"name":"PrintUint","type":"event"}]

remixData = "60606040527f79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817986000557f483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b860015560406040519081016040528060005481526020016001548152506002906002610076929190610120565b5060206040519081016040528060026002806020026040519081016040528092919082600280156100bc576020028201915b8154815260200190600101908083116100a8575b505050505081525060046000820151816000019060026100dd929190610160565b5050507ffffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f600655600560075560066008556007600955341561011b57fe5b6101c5565b826002810192821561014f579160200282015b8281111561014e578251825591602001919060010190610133565b5b50905061015c91906101a0565b5090565b826002810192821561018f579160200282015b8281111561018e578251825591602001919060010190610173565b5b50905061019c91906101a0565b5090565b6101c291905b808211156101be5760008160009055506001016101a6565b5090565b90565b610a35806101d46000396000f30060606040526000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680637422d36414610046578063ecd31f60146102e9575bfe5b341561004e57fe5b610166600480803590602001908201803590602001908080601f0160208091040260200160405190810160405280939291908181526020018383808284378201915050505050509190803590602001908201803590602001908080601f016020809104026020016040519081016040528093929190818152602001838380828437820191505050505050919080359060200190919080359060200190820180359060200190808060200260200160405190810160405280939291908181526020016000905b82821015610158578484839050604002016002806020026040519081016040528092919082600260200280828437820191505050505081526020019060010190610113565b5050505050919050506104b5565b604051808060200180602001858152602001806020018481038452888181518152602001915080519060200190808383600083146101c3575b8051825260208311156101c35760208201915060208101905060208303925061019f565b505050905090810190601f1680156101ef5780820380516001836020036101000a031916815260200191505b50848103835287818151815260200191508051906020019080838360008314610237575b80518252602083111561023757602082019150602081019050602083039250610213565b505050905090810190601f1680156102635780820380516001836020036101000a031916815260200191505b508481038252858181518152602001915080516000925b818410156102d3578284906020019060200201516002602002808383600083146102c3575b8051825260208311156102c35760208201915060208101905060208303925061029f565b505050905001926001019261027a565b9250505097505050505050505060405180910390f35b34156102f157fe5b6104b3600480803590602001908201803590602001908080601f016020809104026020016040519081016040528093929190818152602001838380828437820191505050505050919080359060200190919080359060200190919080359060200190820180359060200190808060200260200160405190810160405280939291908181526020016000905b828210156103c157848483905060400201600280602002604051908101604052809291908260026020028082843782019150505050508152602001906001019061037c565b50505050509190803560001916906020019091908035906020019091908035906020019091908035906020019082018035906020019080806020026020016040519081016040528093929190818152602001838360200280828437820191505050505050919080359060200190919080359060200190820180359060200190808060200260200160405190810160405280939291908181526020016000905b828210156104a5578484839050604002016002806020026040519081016040528092919082600260200280828437820191505050505081526020019060010190610460565b5050505050919050506106c9565b005b6104bd610912565b6104c5610912565b60006104cf610926565b7f551303dd5f39cbfe6daba6b3e27754b8a7d72f519756a2cde2b92c2bbde159a76040518080602001828103825260138152602001807f2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d0000000000000000000000000081525060200191505060405180910390a17f43123f7005ece31cd2478fa2cd0bec5ea2e353c1c3fe9ca390a6de2ab917eac96040518080602001828103825260168152602001807f576520676f742061206e696365206d6573736167653a0000000000000000000081525060200191505060405180910390a17f43123f7005ece31cd2478fa2cd0bec5ea2e353c1c3fe9ca390a6de2ab917eac9886040518080602001828103825283818151815260200191508051906020019080838360008314610610575b805182526020831115610610576020820191506020810190506020830392506105ec565b505050905090810190601f16801561063c5780820380516001836020036101000a031916815260200191505b509250505060405180910390a17f43123f7005ece31cd2478fa2cd0bec5ea2e353c1c3fe9ca390a6de2ab917eac96040518080602001828103825260138152602001807f2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d0000000000000000000000000081525060200191505060405180910390a18787878793509350935093505b945094509450949050565b6000600088518a8c02141515610768577f551303dd5f39cbfe6daba6b3e27754b8a7d72f519756a2cde2b92c2bbde159a760405180806020018281038252602b8152602001807f4d69736d6174636820696e207468652064696d656e73696f6e206f662074686581526020017f206b6579206d617472697800000000000000000000000000000000000000000081525060400191505060405180910390a15b7f43123f7005ece31cd2478fa2cd0bec5ea2e353c1c3fe9ca390a6de2ab917eac98c60405180806020018281038252838181518152602001915080519060200190808383600083146107d9575b8051825260208311156107d9576020820191506020810190506020830392506107b5565b505050905090810190601f1680156108055780820380516001836020036101000a031916815260200191505b509250505060405180910390a1600090505b838110156108885761083f838281518110151561083057fe5b90602001906020020151610897565b828281548110151561084d57fe5b906000526020600020906002020160005b5060008201518160000190600261087692919061093a565b509050505b8080600101915050610817565b5b505050505050505050505050565b61089f61097a565b600060006108ab610994565b8460006002811015156108ba57fe5b60200201516001900492508460016002811015156108d457fe5b60200201516001900491506040604051908101604052808481526020018381525090506020604051908101604052808281525093505b505050919050565b602060405190810160405280600081525090565b602060405190810160405280600081525090565b8260028101928215610969579160200282015b8281111561096857825182559160200191906001019061094d565b5b50905061097691906109bc565b5090565b60406040519081016040528061098e6109e1565b81525090565b6040604051908101604052806002905b60008152602001906001900390816109a45790505090565b6109de91905b808211156109da5760008160009055506001016109c2565b5090565b90565b6040604051908101604052806002905b60008152602001906001900390816109f157905050905600a165627a7a72305820a1da39115e0bdda071c9c8b66b72070b6c38313a01223bc4aa02fbd247873fe20029"





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
         var R = ringct_sol_ringct.R({_from: web3.eth.coinbase})
		// var logErrorStringEvent = ringct_sol_ringct.LogErrorString({_from: web3.eth.coinbase});
		// var printStringEvent = ringct_sol_ringct.PrintString({_from: web3.eth.coinbase});
		// var printBoolEvent = ringct_sol_ringct.PrintBool({_from: web3.eth.coinbase});
		// var printAddressEvent = ringct_sol_ringct.PrintAddress({_from: web3.eth.coinbase});
		// var printUintEvent = ringct_sol_ringct.PrintUint({_from: web3.eth.coinbase});
		console.log("Listening on event")

		R.watch(function(err, result) {
		  if (err) {
		    console.log(err)
		    return;
		  }
		  console.log("res")
		  console.log(JSON.stringify(result.args))
		})
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
		// printUintEvent.watch(function(err, result) {
		//   if (err) {
		//     console.log(err)
		//     return;
		//   }
		//   console.log("uint incoming: " + result.args._value)
		// })

		console.log("sending transaction")
		// x = ringct_sol_ringct.set_s.sendTransaction("h", {from: web3.eth.coinbase})
		// console.log(x)
		console.log("done transaction")
		//ringct_sol_ringct.test.sendTransaction('sendTransaction message', {from: web3.eth.coinbase})


    }
    setTimeout(function(){
		miner.stop()
		console.log("Stoped mining")
	}, 45000);
 })

