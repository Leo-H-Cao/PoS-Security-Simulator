package main

import (
	"PoS-Security-Simulator/pos"
)

func main() {
	//manual or auto
	runType := "auto"
	//100
	numValidators := 10
	//10
	numUsers := 3
	//20, 50, 70
	numMal := 7
	//20
	committeeSize := 4
	//5
	delegateSize := 3
	//pos, slashing, or reputation
	blockchainType := "slashing"
	//network_partition, balance, none
	attack := "network_partition"
	pos.Run(runType, numValidators, numUsers, numMal, committeeSize, delegateSize, blockchainType, attack)
}
