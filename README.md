# Ring Confidential Transaction (RingCT) in an Ethereum Smart Contract


### This is part of a research project. Not to be used in production! (yet at least ;-)


This repository contains two part:
1. A python implementation of RingCT letting users generate and verify valid Ring Confidential Transaction.
2. A solidity implementation of the verification part of a RingCT. 

The goal of this project is to create tokens that could be traded in RingCT providing anonymous payments method to the Ethereum blockchain. Because of the cost of elliptic curve multiplication and addition this is for now not realistic. However, the Ethereum developpers plans to introduce precompiled instructions for the EVM which would make this project realistic. This ReadMe will be updated once the [EIP 102](https://github.com/ethereum/EIPs/issues/102) is live on the main net. 

For test purpose it is best run with [truffle](https://github.com/trufflesuite/truffle).

## RingCT
[RingCT](https://eprint.iacr.org/2015/1098.pdf) is a method to execute anonymous transactions. It is lives on the Monero blockchain. It was proposed by Shen Noether and published in Ledger
It works by creating a ring for each transaction. This way the payment issuer can only be identified as one of people in the ring but not more precisely. 

RingCT also incorpore [Confidential Transaction](https://people.xiph.org/~greg/confidential_values.txt) as proposed by Gregory Maxwell. This way, the amount of the transaction is hidden. It however forces us to use range signature which take a good amount of storage. 

RingCT offers a good balance between privacy and usability. As implemented on the Monero blockchain, it ensure payer anonymity in the set on input public keys, as well as payee anonymity thanks to Stealth Addresses. Thanks to RingCT, most of the attacks that were possible in the early days of Monero. 


## Remaining challenges
This implementation still faces different challenges, some of them could be resolvable in the near future though. For example, like all the anonymous transactions implemented as part of a smart contracts, we didn't solve the problem of who's paying the gas for the contract execution and the information leak that can be associated with it. The implementation of gas balance in Ethereum contracts [EIP 101](https://github.com/ethereum/EIPs/issues/28) would from our current understanding not solve the whole problem but move it a bit further. If you have any idea or contribution on the matter, we are happy to discuss!
The cost of gas of a transaction (currently >1 billion, still obvious place for improvement though) is a big challenge too. We are now also doing some estimation of the cost after the introduction of the compiled ECADD and ECMUL opcode.  

## Further development
This project is still in development. At term, an eventual tokenization is possible as part of an ERC20 token. As stated above, there are still big challenge to solve. We might also relax some privacy contraints if the challenges seem unsolvable.
Other elements are on the road map, like the switch to [Switch commitments](https://eprint.iacr.org/2017/237.pdf) to lighten the size of the range proofs. 

Any contributions is welcome as this is still a side project for the main author.  


## Python implementation
The python implementation can be found in the [offline folder](./offline/). 
### Setup
Dependencies: 

[ecdsa-python](https://github.com/warner/python-ecdsa)

[pysha3](https://github.com/tiran/pysha3)

[ethJsonRPC](https://github.com/vwvw/ethjsonrpc.git)
You will need a modified version of ethJsonRPC. You can install it with 

```bash
pip install git+https://github.com/vwvw/ethjsonrpc.git
```
It is needed because the timeout in the official version is too short for the long running time of the ring verification in the EVM.
[truffle](http://truffleframework.com/)

To run the script you will first need to launch an instance of testrpc.
From your truffle-dapp folder launch the following command:

```bash
node_modules/.bin/testrpc -l100000000000
```

And in another terminal window again from the truffle-dapp folder:
```bash
truffle migrate > contractAddress.txt && cat contractAddress.txt && python3 ../RingCT/offline/ringCT.py
```
The execution of the script is quite long. Especially the verification since it is executed in the EVM, please be patient (~25min on a 2017 laptop).

## Solidity implementation
This implementation can be found in the [online folder](./online/). The ecadd (elliptic curve addition), ecmul (elliptic curve multiplication), JtoA (Jacobian to Affine elliptic curve point transformation) as well as dependant methods are taken from the work of [Selma Steinhoff](https://www.linkedin.com/in/selmasteinhoff/?ppe=1).

## Credits
This repository contain the work done during the spring semester of 2017 as part of an Introduction to Research in Computer Science at ETH Zürich.
I was helped and advised by [Dr Arthur Gervais](http://arthurgervais.com/).
