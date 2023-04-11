package main

import (
	"PoS-Security-Simulator/pos"
)

func main() {
	//manual or auto
	runType := "auto"
	numValidators := 9
	numUsers := 5
	numMal := 5
	committeeSize := 3
	delegateSize := 5
	//pos or reputation
	blockchainType := "pos"
	attack := "balance"
	pos.Run(runType, numValidators, numUsers, numMal, committeeSize, delegateSize, blockchainType, attack)
}
