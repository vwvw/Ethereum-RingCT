#Init blockchain for two nodes in two different directory
#Run this command in both nodes
geth --datadir . init ../eth/genesis.json


#Run one of these command in two terminal window

geth --identity "MyNodeName" --rpc --rpcport "8080" --rpccorsdomain "*" --datadir "~/ethereum/node1" --port "30303" --nodiscover --rpcapi "db,eth,net,web3" --networkid 1999 --jspath "../RingCT" --verbosity 3 console 2>> log.txt


geth --identity "MyNodeName" --rpc --rpcport "8081" --rpccorsdomain "*" --datadir "~/ethereum/node2" --port "30303" --nodiscover --rpcapi "db,eth,net,web3" --networkid 1999 --jspath "../RingCT" --verbosity 3 console 2>> log.txt

#Peers should be empty
admin.peers

#Get enode of one node
admin.nodeInfo.enode

#Connect both nodes by entering in one terminal, with the enode outputted by the previous function
admin.addPeer("output of nodeInfo.enode")

