# Ring Confidential Transaction (RingCT) in an Ethereum Smart Contract


### This was part of a research project. Not to be used in production!


This repository contains two part:
1. A python implementation of RingCT letting users generate and verify valid Ring Confidential Transaction.
2. A solidity implementation of the verification part of a RingCT. 

The goal of this project is to create tokens that could be traded in RingCT providing anonymous payments method to the Ethereum blockchain. Because of the cost of elliptic curve multiplication and addition this is for now not realistic. However, the Ethereum developpers plans to introduce precompiled instructions for the EVM which would make this project realistic. This ReadMe will be updated once the EIP 102 is live on the main net. 

For test purpose it is best run with [truffle](https://github.com/trufflesuite/truffle).

## RingCT:
[RingCT](https://eprint.iacr.org/2015/1098.pdf) is a method to execute anonymous transactions. It is lives on the Monero blockchain. It was proposed by Shen Noether and published in Ledger
It works by creating a ring for each transaction. This way the payment issuer can only be identified as one of people in the ring but not more precisely. 
RingCT also incorpore [Confidential Transaction](https://people.xiph.org/~greg/confidential_values.txt) as proposed by Gregory Maxwell. This way, the amount of the transaction is hidden. It however forces us to use range signature which take a good amount of storage. 

## Python implementation
The python implementation can be found in the [offline folder](./offline/). 
### Setup
Dependencies: [ecdsa-python](https://github.com/warner/python-ecdsa)

## Solidity implementation
This implementation can be found in the [online folder](./online/). The ecadd (elliptic curve addition), ecmul (elliptic curve multiplication), JtoA (Jacobian to Affine elliptic curve point transformation) as well as dependant methods are taken from the work of [Selma Steinhoff](https://www.linkedin.com/in/selmasteinhoff/?ppe=1).

## Credits
This repository contain the work done during the spring semester of 2017 as part of an Introduction to Research in Computer Science at ETH Zürich.
I was helped and advised by [Dr Arthur Gervais](http://arthurgervais.com/).