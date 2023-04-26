package pos

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/exp/slices"
	"gonum.org/v1/gonum/stat/sampleuv"
)

// Blockchain is a series of validated Blocks
var CertifiedBlockchain []Block
var balanceAttackFork []Block

//Temporary blocks if we want to look into finality attacks
// var tempChain []Block

// Slice of validator pointers
var validators = make([]*Validator, 0)

// Slice of delegate pointers
var delegates = make([]*Validator, 0)

// Slice of user pointers who can make transactions
var users = make(map[string]*User)

// Current block proposer
var proposer *Validator = nil

// Validators that will validate the proposed block
var validationCommittee = make([]*Validator, 0)

// Malicious validators
var malValidators = make([]*Validator, 0)

var validatorsSliceLock = &sync.Mutex{}

var committeeSize = 0

var delegateSize = 0

var runConsensusCounter = 0

var currAttack = ""

var forked bool

var forkedCounter = 0

var ForkedBlockchain = make([][]*Validator, 2)

var forkProposer *Validator = nil

var delegateCounter = 0

var roundCount = 0

var startTime = time.Now()

var blockchainType string

func Run(runType string, numValidators int, numUsers int, numMal int, comSize int, delSize int, blkChainType string, attack string) {
	err := godotenv.Load()
	if err != nil {
		log.Fatal(err)
	}
	startTime = time.Now()
	committeeSize = comSize
	delegateSize = delSize
	delegateCounter = 2 * delegateSize
	blockchainType = blkChainType

	currAttack = attack
	for i := range ForkedBlockchain {
		ForkedBlockchain[i] = make([]*Validator, numValidators/2)
	}

	// create genesis block
	t := time.Now()
	genesisBlock := Block{}
	genesisBlock = Block{Index: 0, Timestamp: t.String(), Transactions: []Transaction{}, Hash: calculateBlockHash(genesisBlock), PrevHash: "", Validator: ""}
	CertifiedBlockchain = append(CertifiedBlockchain, genesisBlock)

	if attack == "balance" {
		// create initial fork
		t := time.Now()
		genesisBlockFork := Block{}
		genesisBlockFork = Block{Index: 1, Timestamp: t.String(), Transactions: []Transaction{}, Hash: calculateBlockHash(genesisBlockFork), PrevHash: "", Validator: ""}
		balanceAttackFork = append(balanceAttackFork, genesisBlockFork)
	}

	tcpPort := os.Getenv("PORT")

	// start TCP and serve TCP server
	server, err := net.Listen("tcp", ":"+tcpPort)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("TCP Server Listening on port :", tcpPort)
	defer server.Close()

	//Advances time slots, choosing new proposers that add blocks to the chain and new validation committees
	//Standard proof of stake
	if blockchainType == "pos" || blockchainType == "slashing" {
		if attack == "balance" {
			go func() {
				for {
					balanceNextTimeSlot()
					roundCount++
					if roundCount%10 == 0 {
						printEvaluation()
					}
				}
			}()
		} else {
			go func() {
				for {
					nextTimeSlot()
					roundCount++
					if roundCount%10 == 0 {
						printEvaluation()
					}
				}
			}()
		}
	} else if blockchainType == "reputation" {
		if attack == "balance" {
			go func() {
				for {
					balanceReputationNextTimeSlot()
					roundCount++
					if roundCount%10 == 0 {
						printEvaluation()
					}
				}
			}()
		} else {
			go func() {
				for {
					nextReputationTimeSlot()
					roundCount++
					if roundCount%10 == 0 {
						printEvaluation()
					}
				}
			}()
		}
	} else {
		fmt.Println("Invalid blockchain type")
		return
	}

	//auto create connections
	go func() {
		if runType == "manual" {
			return
		}

		if attack == "balance" {
			createBalanceAttackConnections(numValidators, numMal, runType, numUsers)
		} else {
			for numValidators > 0 {
				conn, err := net.Dial("tcp", ":9000")
				if err != nil {
					fmt.Println("Error connecting:", err)
					return
				}
				malString := "n"
				if numMal > 0 {
					malString = "y"
					numMal--
				}
				go handleConnection(conn, runType, "v", malString, false)
				numValidators--
			}
			for numUsers > 0 {
				conn, err := net.Dial("tcp", ":9000")
				if err != nil {
					fmt.Println("Error connecting:", err)
					return
				}
				if err != nil {
					log.Fatal(err)
				}
				go handleConnection(conn, runType, "u", "", false)
				numUsers--
			}
		}
	}()
	//Accepts connections joining the network
	for {
		conn, err := server.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handleConnection(conn, runType, "", "", false)
	}

}

func createBalanceAttackConnections(numValidators int, numMal int, runType string, numUsers int) {
	// split views of validators if balance attack
	viewForkedChain := false
	numHonestValidators := numValidators - numMal
	honestValidatorsSplit := 0
	malValidatorsSplit := 0
	originalNumMal := numMal

	for numValidators > 0 {

		// make only half of the validators see one side of fork for balance attack
		if numMal == 0 && honestValidatorsSplit <= numHonestValidators/2 {
			viewForkedChain = true
		} else if numMal > 0 && malValidatorsSplit < originalNumMal/2 {
			viewForkedChain = true
		} else {
			viewForkedChain = false
		}

		conn, err := net.Dial("tcp", ":9000")
		if err != nil {
			fmt.Println("Error connecting:", err)
			return
		}
		malString := "n"
		if numMal > 0 {
			malString = "y"
			numMal--
			if viewForkedChain {
				malValidatorsSplit++
			}
		} else {
			honestValidatorsSplit++
		}

		go handleConnection(conn, runType, "v", malString, viewForkedChain)
		numValidators--
	}
	for numUsers > 0 {
		conn, err := net.Dial("tcp", ":9000")
		if err != nil {
			fmt.Println("Error connecting:", err)
			return
		}
		if err != nil {
			log.Fatal(err)
		}
		go handleConnection(conn, runType, "u", "", viewForkedChain)
		numUsers--
	}
}

func chooseValidationCommittee(validators []*Validator, committeeSize int) []*Validator {
	//make a slice of stakes for weighted dsitribution
	validatorsSliceLock.Lock()
	stakeWeights := make([]float64, len(validators))
	for i, validator := range validators {
		stakeWeights[i] = validator.Stake
	}
	validatorsSliceLock.Unlock()

	validationCommittee := make([]*Validator, 0)
	weightedDist := sampleuv.NewWeighted(stakeWeights, nil)
	for i := 0; i < committeeSize; i++ {
		index, isOk := weightedDist.Take()
		if isOk {
			validationCommittee = append(validationCommittee, validators[index])
		} else {
			break
		}
	}
	return validationCommittee
}

func chooseDelegates(validators []*Validator, delegateSize int) []*Validator {

	validatorMap := make(map[string]*Validator)

	//send delegate vote requests to all validators
	validatorsSliceLock.Lock()
	for _, validator := range validators {
		validatorMap[validator.Address] = validator
		msg := DelegateVoteRequestMessage{
			delegateSize: delegateSize,
		}
		validator.delegateVoteRequestChannel <- msg
	}
	validatorsSliceLock.Unlock()
	//Recieve and tally up votes, punishing those who voted for someone with less reputation
	delegateResultMap := make(map[string]int)
	for _, validator := range validators {
		msg := <-validator.delegateVoteChannel
		validator.reputation = math.Min(100, validator.reputation+1)
		for _, validatorVoted := range msg.delegateVotes {
			delegateResultMap[validatorVoted.Address] += 1
		}
	}
	//select the winners
	validatorAddresses := make([]string, len(delegateResultMap))
	for va := range delegateResultMap {
		validatorAddresses = append(validatorAddresses, va)
	}

	sort.Slice(validatorAddresses, func(i, j int) bool {
		return delegateResultMap[validatorAddresses[i]] > delegateResultMap[validatorAddresses[j]]
	})

	validatorAddresses = validatorAddresses[:delegateSize]
	delegates = make([]*Validator, 0)
	for _, validatorAddress := range validatorAddresses {
		delegates = append(delegates, validatorMap[validatorAddress])
	}
	return delegates

}

func chooseBlockProposer() *Validator {
	if len(validationCommittee) == 0 {
		return nil
	}

	totalWeight := 0.0
	for _, validator := range validationCommittee {
		totalWeight += validator.Stake
	}

	randomNumber := 0.0
	rand.Seed(time.Now().UnixNano())
	randomNumber = rand.Float64() * totalWeight

	weightSum := 0.0
	for _, validator := range validationCommittee {
		weightSum += validator.Stake
		if weightSum >= randomNumber {
			return validator
		}
	}
	return nil
}

func balanceLongestChainConsensus() {
	longestLength := -1
	secondLongestLength := -1
	var longestValidator *Validator = nil
	for _, validator := range validators {
		// + 1 to check for second longest chain for balance attack
		if len(validator.Blockchain)+1 >= longestLength {
			if longestLength == -1 && len(validator.Blockchain) > longestLength {
				longestValidator = validator
				longestLength = len(validator.Blockchain)
				continue
			}

			longestValidatorLastBlock := longestValidator.Blockchain[len(longestValidator.Blockchain)-1]
			curValidatorLastBlock := validator.Blockchain[len(validator.Blockchain)-1]

			if longestValidatorLastBlock.Hash != curValidatorLastBlock.Hash {
				if len(validator.Blockchain) > longestLength {
					secondLongestLength = longestLength
					longestValidator = validator
					longestLength = len(validator.Blockchain)
				} else {
					secondLongestLength = len(validator.Blockchain)
				}
			}
		}
	}
	if longestLength-secondLongestLength <= 1 {
		fmt.Println("Longest chain consensus delayed")
	} else {
		CertifiedBlockchain = make([]Block, len(longestValidator.Blockchain))
		copy(CertifiedBlockchain, longestValidator.Blockchain)

		for _, validator := range validators {
			//broadcast the verified transactions to all blocks
			if validator.Address == longestValidator.Address {
				continue
			}
			blockChainBuffer := make([]Block, len(CertifiedBlockchain))
			copy(blockChainBuffer, CertifiedBlockchain)
			longestValidator.transactionPoolLock.Lock()
			unconfirmedTransactionsBuffer := make(map[int]Transaction)
			for id, transaction := range longestValidator.unconfirmedTransactions {
				unconfirmedTransactionsBuffer[id] = transaction
			}
			confirmedTransactionsBuffer := make(map[int]bool)
			for id, status := range longestValidator.confirmedTransactions {
				confirmedTransactionsBuffer[id] = status
			}
			longestValidator.transactionPoolLock.Unlock()
			validator.Blockchain = blockChainBuffer
			validator.unconfirmedTransactions = unconfirmedTransactionsBuffer
			validator.confirmedTransactions = confirmedTransactionsBuffer
		}
		//slash fork proposer if there was a fork
		if forked {
			fmt.Printf("SLASHED FORK PROPOSER")
			if blockchainType == "slashing" {
				forkProposer.Stake *= 0.2
			}
			if blockchainType == "reputation" {
				forkProposer.reputation *= 0.2
			}
			forkProposer = nil
		}

		forked = false
	}
}

func longestChainConsensus() {
	longestLength := -1
	var longestValidator *Validator = nil
	for _, validator := range validators {
		if len(validator.Blockchain) > longestLength {
			longestValidator = validator
			longestLength = len(validator.Blockchain)
		}
	}

	CertifiedBlockchain = make([]Block, len(longestValidator.Blockchain))
	copy(CertifiedBlockchain, longestValidator.Blockchain)

	for _, validator := range validators {
		//broadcast the verified transactions to all blocks
		if validator.Address == longestValidator.Address {
			continue
		}
		blockChainBuffer := make([]Block, len(CertifiedBlockchain))
		copy(blockChainBuffer, CertifiedBlockchain)

		longestValidator.transactionPoolLock.Lock()
		unconfirmedTransactionsBuffer := make(map[int]Transaction)
		for id, transaction := range longestValidator.unconfirmedTransactions {
			unconfirmedTransactionsBuffer[id] = transaction
		}

		confirmedTransactionsBuffer := make(map[int]bool)
		for id, status := range longestValidator.confirmedTransactions {
			confirmedTransactionsBuffer[id] = status
		}
		longestValidator.transactionPoolLock.Unlock()

		validator.Blockchain = blockChainBuffer
		validator.unconfirmedTransactions = unconfirmedTransactionsBuffer
		validator.confirmedTransactions = confirmedTransactionsBuffer
	}

	//slash fork proposer if there was a fork
	if forked {
		if blockchainType == "pos" || blockchainType == "slashing" {
			fmt.Printf("SLASHED FORK PROPOSER")
			if blockchainType == "slashing" {
				forkProposer.Stake *= 0.2
			}
			forkProposer = nil
		} else if blockchainType == "reputation" {
			fmt.Printf("SLASHED FORK PROPOSER")
			forkProposer.reputation *= 0.2
			forkProposer = nil
		}

	}

	forked = false
}
func balancePrintInfo() {
	printString := ""
	for _, block := range CertifiedBlockchain {
		printString += "->["
		for _, transaction := range block.Transactions {
			printString += fmt.Sprintf("%d,", transaction.ID)
		}
		printString = printString[:len(printString)-1]
		printString += "]"
	}

	printString = printString[1:]
	println("BLOCKCHAIN")
	println(printString)

	//prints User balances
	// println("User balances")
	// for user := range users {
	// 	fmt.Printf("%s: %f\n", users[user].Name, users[user].Balance)
	// }

	//prints Validator balances
	println("Validator balances")
	for _, validator := range validators {
		fmt.Printf("%s: %f, %d, Evil: %t \n", validator.Address[:3], validator.Stake, validator.committeeCount, validator.IsMalicious)
		printString := ""
		for _, block := range validator.Blockchain {
			printString += "->["
			for _, transaction := range block.Transactions {
				printString += fmt.Sprintf("%d,", transaction.ID)
			}
			printString = printString[:len(printString)-1]
			printString += "]"
		}
		printString = printString[1:]
		fmt.Printf("VALIDATOR %s BLOCKCHAIN\n", validator.Address[:3])
		println(printString)
	}
}

func printInfo() {
	// println("Delegates")
	// for _, delegate := range delegates {
	// 	println(delegate.Address[:3])
	// }

	printString := ""
	for _, block := range CertifiedBlockchain {
		printString += "->["
		for _, transaction := range block.Transactions {
			printString += fmt.Sprintf("%d,", transaction.ID)
		}
		printString = printString[:len(printString)-1]
		printString += "]"
	}

	printString = printString[1:]
	println("BLOCKCHAIN")
	println(printString)

	//prints User balances
	// println("User balances")
	// for user := range users {
	// 	fmt.Printf("%s: %f\n", users[user].Name, users[user].Balance)
	// }

	//prints Validator balances
	println("Validator balances")
	for _, validator := range validators {
		fmt.Printf("%s: %f, %f\n", validator.Address[:3], validator.Stake, validator.reputation)
		// printString := ""
		// for _, block := range validator.Blockchain {
		// 	printString += "->["
		// 	for _, transaction := range block.Transactions {
		// 		printString += fmt.Sprintf("%d,", transaction.ID)
		// 	}
		// 	printString = printString[:len(printString)-1]
		// 	printString += "]"
		// }
		// printString = printString[1:]
		// fmt.Printf("VALIDATOR %s BLOCKCHAIN\n", validator.Address[:3])
		// println(printString)
	}

	//prints Forked group
	// if currAttack == "network_partition" {
	// 	println("Fork Groups")
	// 	for i := 0; i < len(ForkedBlockchain); i++ {
	// 		for j := 0; j < len(ForkedBlockchain[i]); j++ {
	// 			if ForkedBlockchain[i][j] != nil {
	// 				var validator = *ForkedBlockchain[i][j]
	// 				fmt.Printf("%s ", validator.Address[:3])
	// 			} else {
	// 				fmt.Printf("nil ")
	// 			}
	// 		}
	// 		fmt.Println()
	// 	}
	// }
}

func balanceNextTimeSlot() {
	time.Sleep(5 * time.Second)
	fmt.Printf("\nTime slot %s\n\n", time.Now().Format("15:04:05"))
	runConsensusCounter += 1

	if runConsensusCounter >= 5 {
		balanceLongestChainConsensus()
		runConsensusCounter = 0
	}

	//randomly choose new committee of a third of all validators who will validate the new block
	validationCommittee = chooseValidationCommittee(validators, committeeSize)
	fmt.Println("New validation committee chosen")
	for _, commit := range validationCommittee {
		commit.committeeCount += 1
		// fmt.Println(commit.Address[:3])
	}
	//Choose a new block proposer based on stake
	proposer = chooseBlockProposer()
	if proposer == nil {
		return
	}
	proposer.proposerCount += 1
	fmt.Printf("Proposer %s chosen as new block proposer\n", proposer.Address[:3])

	//block proposer chooses a new block
	newBlock, err := generateBlock(proposer)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// find length of the shorter fork
	validatorsSliceLock.Lock()
	shorterForkLength := math.MaxInt32
	fmt.Println("Printing validator blockchains")
	for _, validator := range validators {
		if len(validator.Blockchain) < shorterForkLength {
			shorterForkLength = len(validator.Blockchain)
		}
	}
	validatorsSliceLock.Unlock()

	//let malicious validators know if they should vote for/against block to balance
	malVote := false
	if len(proposer.Blockchain) == shorterForkLength {
		malVote = true
	}

	fmt.Printf("Block %d chosen as new block\n", newBlock.Index)

	//validation committee validates blocks
	//broadcast block to all members of committee
	for _, validator := range validationCommittee {
		msg := ValidateBlockMessage{
			newBlock: newBlock,
			malVote:  malVote,
		}
		validator.incomingChannel <- msg
	}

	// Process validation results
	validCount := 0
	invalidCount := 0
	validationResults := make(map[string]bool)
	for _, validator := range validationCommittee {
		msg := <-validator.outgoingChannel
		switch msg := msg.(type) { // Use type assertion to determine the type of the received message
		case ValidationStatusMessage:
			validationResults[validator.Address] = msg.isValid
			if msg.isValid == true {
				validCount++
			} else {
				invalidCount++
			}
		default:
			fmt.Printf("Received an unknown struct: %+v\n", msg)
			fmt.Printf("%T\n", msg)
		}
	}

	// fmt.Printf("Voting results\nInvalid Count: %d\nValid Count: %d\nCommittee size: %d\n", invalidCount, validCount, len(validationCommittee))

	//add block if majority believe block is valid
	isValid := validCount > len(validationCommittee)/2
	if isValid {
		// proposer.Blockchain = append(proposer.Blockchain, newBlock)
		println("Valid block added to blockchain")
		proposer.blockSuccessCount += 1

		//broadcast the verified transactions to all blocks
		msg := VerifiedBlockMessage{
			transactions: newBlock.Transactions,
			newBlock:     newBlock,
		}
		for _, validator := range validators {
			validator.incomingChannel <- msg
		}

		//Update transactional amounts and reward proposer
		for _, transaction := range newBlock.Transactions {
			transaction.Sender.Balance -= (transaction.Amount + transaction.Reward)
			transaction.Receiver.Balance += transaction.Amount
			proposer.Stake += transaction.Reward

			senderString := fmt.Sprintf("New balance: %f\n", transaction.Sender.Balance)
			io.WriteString(transaction.Sender.conn, senderString)

			receiverString := fmt.Sprintf("New balance: %f\n", transaction.Receiver.Balance)
			io.WriteString(transaction.Receiver.conn, receiverString)
		}
	} else {
		println("Committee votes block invalid")
		if blockchainType == "slashing" {
			proposer.Stake *= 0.2
		}
	}
	//punish validators who voted against the majority
	slashPercentage := 0.2
	for _, validator := range validationCommittee {
		if isValid {
			if validationResults[validator.Address] == false {
				if blockchainType == "slashing" {
					validator.Stake *= slashPercentage
				}
			}
		} else {
			if validationResults[validator.Address] == true {
				if blockchainType == "slashing" {
					validator.Stake *= slashPercentage
				}
			}
		}
	}

	balancePrintInfo()
}

func printEvaluation() {
	//print malicious nodes

	println("\nRESULTS\n")
	fmt.Printf("Total blocks: %d\n", len(CertifiedBlockchain))

	malBlockCount := 0
	transactionCount := 0
	for _, block := range CertifiedBlockchain {
		if block.IsMalicious {
			malBlockCount++
		}
		transactionCount += len(block.Transactions)
	}
	fmt.Printf("Malicious blocks: %d\n", malBlockCount)
	fmt.Printf("Transactions validated: %d\n", transactionCount)
	fmt.Printf("Time so far: %f\n", time.Now().Sub(startTime).Seconds())
}

func nextTimeSlot() {

	//wait 5 seconds every slot
	time.Sleep(5 * time.Second)

	if len(validators) == 0 {
		return
	}

	fmt.Printf("\nTime slot %s\n\n", time.Now().Format("15:04:05"))

	runConsensusCounter += 1

	if runConsensusCounter >= 5 {
		longestChainConsensus()
		runConsensusCounter = 0
	}

	//randomly choose new committee of a third of all validators who will validate the new block
	validationCommittee = chooseValidationCommittee(validators, committeeSize)
	fmt.Println("New validation committee chosen")
	for _, commit := range validationCommittee {
		commit.committeeCount += 1
		// fmt.Println(commit.Address[:3])
	}
	//Choose a new block proposer based on stake
	proposer = chooseBlockProposer()
	if proposer == nil {
		return
	}
	proposer.proposerCount += 1
	fmt.Printf("Proposer %s chosen as new block proposer\n", proposer.Address[:3])

	//block proposer chooses a new block

	//check what group proposer is in
	proposerGroup := 1
	if slices.Contains(ForkedBlockchain[0], proposer) {
		proposerGroup = 0
	}

	// oldBlock := Blockchain[len(Blockchain)-1]
	newBlock, err := generateBlock(proposer)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	evilProposer := false

	if proposer.IsMalicious {
		evilProposer = true
	}

	var newBlockTwo Block
	if currAttack == "network_partition" && evilProposer {
		println("EVIL PROPOSER DOING WORK")
		newBlockTwo, err = generateBlock(proposer)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
	} else {
		newBlockTwo = Block{}
	}

	fmt.Printf("Block %d chosen as new block\n", newBlock.Index)

	//validation committee validates blocks
	//broadcast block to all members of committee
	for _, validator := range validationCommittee {
		if currAttack == "network_partition" && evilProposer && !forked {
			if evilProposer {
				msg := ValidateShortAttackBlockMessage{
					newBlock:    newBlock,
					newBlockTwo: newBlockTwo,
				}
				validator.incomingChannel <- msg
			}
		} else {
			msg := ValidateBlockMessage{
				newBlock: newBlock,
			}
			validator.incomingChannel <- msg
		}
	}

	// Process validation results
	validCount := 0
	invalidCount := 0
	validTwoCount := 0
	invalidTwoCount := 0
	validationResults := make(map[string]bool)
	// validationResultsTwo := make(map[string]bool)
	for _, validator := range validationCommittee {
		msg := <-validator.outgoingChannel
		switch msg := msg.(type) { // Use type assertion to determine the type of the received message
		case ValidationStatusMessage:
			validationResults[validator.Address] = msg.isValid
			if msg.isValid == true {
				validCount++
			} else {
				invalidCount++
			}
		case ValidationShortAttackStatusMessage:
			validationResults[validator.Address] = msg.isValid
			validationResults[validator.Address] = msg.isValidTwo
			if msg.isValid == true {
				validCount++
			} else {
				invalidCount++
			}
			if msg.isValidTwo == true {
				validTwoCount++
			} else {
				invalidTwoCount++
			}
		default:
			fmt.Printf("Received an unknown struct: %+v\n", msg)
			fmt.Printf("%T\n", msg)
		}
	}

	if currAttack == "network_partition" && (forked || evilProposer) {
		// fmt.Printf("Voting results\nInvalid Count: %d\nValid Count: %d\nInvalid Two Count: %d\nValid Two Count: %d\nCommittee size: %d\n", invalidCount, validCount, invalidTwoCount, validTwoCount, len(validationCommittee))
	} else {
		// fmt.Printf("Voting results\nInvalid Count: %d\nValid Count: %d\nCommittee size: %d\n", invalidCount, validCount, len(validationCommittee))
	}

	//chain is forked
	if forked {
		println("Chain is forked")
		isValid := validCount >= len(validationCommittee)/2
		if isValid {
			//broadcast the verified transactions to only right branch-- branch with proposer
			for _, validator := range validators {
				if slices.Contains(ForkedBlockchain[proposerGroup], validator) {
					msg := VerifiedShortAttackBlockMessage{
						transactions: newBlock.Transactions,
						newBlock:     newBlock,
					}
					validator.incomingChannel <- msg
				}
			}

			//Update transactional amounts and reward proposer
			for _, transaction := range newBlock.Transactions {
				transaction.Sender.Balance -= (transaction.Amount + transaction.Reward)
				transaction.Receiver.Balance += transaction.Amount
				proposer.Stake += transaction.Reward

				senderString := fmt.Sprintf("New balance: %f\n", transaction.Sender.Balance)
				io.WriteString(transaction.Sender.conn, senderString)

				receiverString := fmt.Sprintf("New balance: %f\n", transaction.Receiver.Balance)
				io.WriteString(transaction.Receiver.conn, receiverString)
			}
			println("Valid block added to blockchain")
		} else {
			println("Committee votes block invalid")
			if blockchainType == "slashing" {
				proposer.Stake *= 0.2
			}
		}

		if blockchainType == "slashing" {
			slashPercentage := 0.2
			for _, validator := range validationCommittee {
				if isValid {
					if validationResults[validator.Address] == false {
						validator.Stake *= slashPercentage
					}
				} else {
					if validationResults[validator.Address] == true {
						validator.Stake *= slashPercentage
					}
				}
			}
		}
		printInfo()
		return
	}

	//short range attack
	if currAttack == "network_partition" && evilProposer {
		isValid := validCount >= len(validationCommittee)/2
		isValidTwo := validTwoCount >= len(validationCommittee)/2

		if isValid {
			//broadcast the verified transactions to all blocks within proposer's group
			for _, validator := range validators {
				if slices.Contains(ForkedBlockchain[proposerGroup], validator) {
					msg := VerifiedShortAttackBlockMessage{
						transactions: newBlock.Transactions,
						newBlock:     newBlock,
					}
					validator.incomingChannel <- msg
				}
			}

			//Update transactional amounts and reward proposer
			for _, transaction := range newBlock.Transactions {
				transaction.Sender.Balance -= (transaction.Amount + transaction.Reward)
				transaction.Receiver.Balance += transaction.Amount
				proposer.Stake += transaction.Reward

				senderString := fmt.Sprintf("New balance: %f\n", transaction.Sender.Balance)
				io.WriteString(transaction.Sender.conn, senderString)

				receiverString := fmt.Sprintf("New balance: %f\n", transaction.Receiver.Balance)
				io.WriteString(transaction.Receiver.conn, receiverString)
			}
			println("Valid block added to blockchain")
		} else {
			println("Committee votes block invalid")
			if blockchainType == "slashing" {
				proposer.Stake *= 0.2
			}
		}
		if isValidTwo {
			//broadcast the verified transactions to all blocks not witihin proposer's group
			for _, validator := range validators {
				if !slices.Contains(ForkedBlockchain[proposerGroup], validator) {
					msg := VerifiedShortAttackBlockTwoMessage{
						transactions: newBlockTwo.Transactions,
						newBlockTwo:  newBlockTwo,
					}
					validator.incomingChannel <- msg
				}
			}

			//Update transactional amounts and reward proposer
			for _, transaction := range newBlockTwo.Transactions {
				transaction.Sender.Balance -= (transaction.Amount + transaction.Reward)
				transaction.Receiver.Balance += transaction.Amount
				proposer.Stake += transaction.Reward

				senderString := fmt.Sprintf("New balance: %f\n", transaction.Sender.Balance)
				io.WriteString(transaction.Sender.conn, senderString)

				receiverString := fmt.Sprintf("New balance: %f\n", transaction.Receiver.Balance)
				io.WriteString(transaction.Receiver.conn, receiverString)
			}
			println("Valid block added to blockchain")
		} else {
			println("Committee votes block invalid")
			if blockchainType == "slashing" {
				proposer.Stake *= 0.2
			}
		}
		if isValid && isValidTwo {
			forked = true
			forkProposer = proposer
		}
		//punish validators who voted against the majority
		// slashPercentage := 0.2
		// for _, validator := range validationCommittee {
		// 	if isValid {
		// 		if validationResults[validator.Address] == false {
		// 			validator.Stake *= slashPercentage
		// 		}
		// 	} else {
		// 		if validationResults[validator.Address] == true {
		// 			validator.Stake *= slashPercentage
		// 		}
		// 	}

		// 	if isValidTwo {
		// 		if validationResultsTwo[validator.Address] == false {
		// 			validator.Stake *= slashPercentage
		// 		}
		// 	} else {
		// 		if validationResultsTwo[validator.Address] == true {
		// 			validator.Stake *= slashPercentage
		// 		}
		// 	}
		// }
		printInfo()
		return
	}

	isValid := validCount >= len(validationCommittee)/2
	if isValid {
		// proposer.Blockchain = append(proposer.Blockchain, newBlock)
		println("Valid block added to blockchain")
		proposer.blockSuccessCount += 1

		//broadcast the verified transactions to all blocks
		msg := VerifiedBlockMessage{
			transactions: newBlock.Transactions,
			newBlock:     newBlock,
		}
		for _, validator := range validators {
			validator.incomingChannel <- msg
		}

		//Update transactional amounts and reward proposer
		for _, transaction := range newBlock.Transactions {
			transaction.Sender.Balance -= (transaction.Amount + transaction.Reward)
			transaction.Receiver.Balance += transaction.Amount
			proposer.Stake += transaction.Reward

			senderString := fmt.Sprintf("New balance: %f\n", transaction.Sender.Balance)
			io.WriteString(transaction.Sender.conn, senderString)

			receiverString := fmt.Sprintf("New balance: %f\n", transaction.Receiver.Balance)
			io.WriteString(transaction.Receiver.conn, receiverString)
		}
	} else {
		println("Committee votes block invalid")
		if blockchainType == "slashing" {
			proposer.Stake *= 0.2
		}
	}
	//punish validators who voted against the majority
	slashPercentage := 0.2
	for _, validator := range validationCommittee {
		if isValid {
			if validationResults[validator.Address] == false {
				println("VALIDATED FALSE WHEN IT WAS TRUE")
				if blockchainType == "slashing" {
					validator.Stake *= slashPercentage
				}
			}
		} else {
			if validationResults[validator.Address] == true {
				println("VALIDATED TRUE WHEN IT WAS FALSE")
				if blockchainType == "slashing" {
					validator.Stake *= slashPercentage
				}
			}
		}
	}
	printInfo()
}

func balanceReputationNextTimeSlot() {
	//wait 5 seconds every slot
	time.Sleep(5 * time.Second)
	fmt.Printf("\nTime slot %s\n\n", time.Now().Format("15:04:05"))
	runConsensusCounter += 1

	if runConsensusCounter >= 5 {
		balanceLongestChainConsensus()
		runConsensusCounter = 0
	}

	//Choose new delegates
	if delegateCounter == 2*delegateSize {
		delegateCounter = 0
		delegates = chooseDelegates(validators, delegateSize)
		fmt.Println("New delegates chosen")
	}

	//Choose next sequential block proposer from delegates
	proposer = delegates[delegateCounter%delegateSize]
	delegateCounter += 1
	proposer.proposerCount += 1
	fmt.Printf("Proposer %s chosen as new block proposer\n", proposer.Address[:3])

	// find length of the shorter fork
	validatorsSliceLock.Lock()
	shorterForkLength := math.MaxInt32
	fmt.Println("printing validator blockchains")
	for _, validator := range validators {
		if len(validator.Blockchain) < shorterForkLength {
			shorterForkLength = len(validator.Blockchain)
		}
	}
	validatorsSliceLock.Unlock()

	//block proposer chooses a new block
	newBlock, err := generateBlock(proposer)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Printf("Block %d chosen as new block\n", newBlock.Index)

	//let malicious validators know if they should vote for/against block to balance
	malVote := false
	if len(proposer.Blockchain) == shorterForkLength {
		malVote = true
	}

	//validation committee validates blocks
	//broadcast block to all members of committee
	for _, validator := range delegates {
		msg := ValidateBlockMessage{
			newBlock: newBlock,
			malVote:  malVote,
		}
		validator.incomingChannel <- msg
	}

	// Process validation results
	validCount := 0
	invalidCount := 0
	validationResults := make(map[string]bool)
	for _, validator := range delegates {
		msg := <-validator.outgoingChannel
		switch msg := msg.(type) { // Use type assertion to determine the type of the received message
		case ValidationStatusMessage:
			validationResults[validator.Address] = msg.isValid
			if msg.isValid == true {
				validCount++
			} else {
				invalidCount++
			}
		default:
			fmt.Printf("Received an unknown struct: %+v\n", msg)
			fmt.Printf("%T\n", msg)
		}
	}

	// fmt.Printf("Voting results\nInvalid Count: %d\nValid Count: %d\nCommittee size: %d\n", invalidCount, validCount, len(delegates))

	//add block if majority believe block is valid
	isValid := validCount > len(delegates)/2
	if isValid {
		println("Valid block added to blockchain")
		proposer.blockSuccessCount += 1
		proposer.reputation = math.Min(100, proposer.reputation+1)
		//broadcast the verified transactions to all blocks
		msg := VerifiedBlockMessage{
			transactions: newBlock.Transactions,
			newBlock:     newBlock,
		}
		for _, validator := range validators {
			validator.incomingChannel <- msg
		}

		//Update transactional amounts and reward proposer
		for _, transaction := range newBlock.Transactions {
			transaction.Sender.Balance -= (transaction.Amount + transaction.Reward)
			transaction.Receiver.Balance += transaction.Amount
			proposer.Stake += transaction.Reward

			senderString := fmt.Sprintf("New balance: %f\n", transaction.Sender.Balance)
			io.WriteString(transaction.Sender.conn, senderString)

			receiverString := fmt.Sprintf("New balance: %f\n", transaction.Receiver.Balance)
			io.WriteString(transaction.Receiver.conn, receiverString)
		}
	} else {
		println("Committee votes block invalid")
		proposer.reputation *= 0.2
	}
	//punish validators who voted against the majority
	for _, validator := range delegates {
		if isValid {
			//Block was valid, but voted invalid
			if validationResults[validator.Address] == false {
				validator.reputation *= 0.5
			} else {
				validator.reputation = math.Min(100, 1+validator.reputation)
			}
		} else {
			//Block invalid, but voted valid
			if validationResults[validator.Address] == true {
				validator.reputation *= 0.5
			} else {
				validator.reputation = math.Min(100, 1+validator.reputation)
			}
		}
	}

	balancePrintInfo()

}

func nextReputationTimeSlot() {
	//wait 5 seconds every slot
	time.Sleep(5 * time.Second)
	fmt.Printf("\nTime slot %s\n\n", time.Now().Format("15:04:05"))
	runConsensusCounter += 1

	if runConsensusCounter >= 5 {
		longestChainConsensus()
		runConsensusCounter = 0
	}

	//Choose new delegates
	if delegateCounter == 2*delegateSize {
		delegateCounter = 0
		delegates = chooseDelegates(validators, delegateSize)
		fmt.Println("New delegates chosen")
	}

	//Choose next sequential block proposer from delegates
	proposer = delegates[delegateCounter%delegateSize]
	delegateCounter += 1
	proposer.proposerCount += 1
	fmt.Printf("Proposer %s chosen as new block proposer\n", proposer.Address[:3])

	//block proposer chooses a new block

	//check what group proposer is in
	proposerGroup := 1
	if slices.Contains(ForkedBlockchain[0], proposer) {
		proposerGroup = 0
	}

	newBlock, err := generateBlock(proposer)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	evilProposer := false

	if proposer.IsMalicious {
		evilProposer = true
	}

	var newBlockTwo Block
	if currAttack == "network_partition" && evilProposer {
		println("EVIL PROPOSER DOING WORK")
		newBlockTwo, err = generateBlock(proposer)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
	} else {
		newBlockTwo = Block{}
	}

	fmt.Printf("Block %d chosen as new block\n", newBlock.Index)

	//validation committee validates blocks
	//broadcast block to all members of committee
	for _, validator := range delegates {
		if currAttack == "network_partition" && evilProposer && !forked {
			if evilProposer {
				msg := ValidateShortAttackBlockMessage{
					newBlock:    newBlock,
					newBlockTwo: newBlockTwo,
				}
				validator.incomingChannel <- msg
			}
		} else {
			msg := ValidateBlockMessage{
				newBlock: newBlock,
			}
			validator.incomingChannel <- msg
		}
	}

	// Process validation results
	validCount := 0
	invalidCount := 0
	validTwoCount := 0
	invalidTwoCount := 0
	validationResults := make(map[string]bool)
	for _, validator := range delegates {
		msg := <-validator.outgoingChannel
		switch msg := msg.(type) { // Use type assertion to determine the type of the received message
		case ValidationStatusMessage:
			validationResults[validator.Address] = msg.isValid
			if msg.isValid == true {
				validCount++
			} else {
				invalidCount++
			}
		case ValidationShortAttackStatusMessage:
			validationResults[validator.Address] = msg.isValid
			validationResults[validator.Address] = msg.isValidTwo
			if msg.isValid == true {
				validCount++
			} else {
				invalidCount++
			}
			if msg.isValidTwo == true {
				validTwoCount++
			} else {
				invalidTwoCount++
			}
		default:
			fmt.Printf("Received an unknown struct: %+v\n", msg)
			fmt.Printf("%T\n", msg)
		}
	}
	// fmt.Printf("Voting results\nInvalid Count: %d\nValid Count: %d\nCommittee size: %d\n", invalidCount, validCount, len(validationCommittee))
	if currAttack == "network_partition" && (forked || evilProposer) {
		// fmt.Printf("Voting results\nInvalid Count: %d\nValid Count: %d\nInvalid Two Count: %d\nValid Two Count: %d\nCommittee size: %d\n", invalidCount, validCount, invalidTwoCount, validTwoCount, len(delegates))
	} else {
		// fmt.Printf("Voting results\nInvalid Count: %d\nValid Count: %d\nCommittee size: %d\n", invalidCount, validCount, len(delegates))
	}

	//chain is forked
	if forked {
		println("Chain is forked")

		//add block if majority believe block is valid
		isValid := validCount >= len(delegates)/2
		if isValid {
			println("Valid block added to blockchain")
			proposer.blockSuccessCount += 1
			proposer.reputation = math.Min(100, proposer.reputation+1)
			//broadcast the verified transactions to all blocks
			for _, validator := range validators {
				if slices.Contains(ForkedBlockchain[proposerGroup], validator) {
					msg := VerifiedShortAttackBlockMessage{
						transactions: newBlock.Transactions,
						newBlock:     newBlock,
					}
					validator.incomingChannel <- msg
				}
			}

			//Update transactional amounts and reward proposer
			for _, transaction := range newBlock.Transactions {
				transaction.Sender.Balance -= (transaction.Amount + transaction.Reward)
				transaction.Receiver.Balance += transaction.Amount
				proposer.Stake += transaction.Reward

				senderString := fmt.Sprintf("New balance: %f\n", transaction.Sender.Balance)
				io.WriteString(transaction.Sender.conn, senderString)

				receiverString := fmt.Sprintf("New balance: %f\n", transaction.Receiver.Balance)
				io.WriteString(transaction.Receiver.conn, receiverString)
			}
		} else {
			println("Committee votes block invalid")
			proposer.reputation *= 0.2
		}
		//punish validators who voted against the majority
		for _, validator := range delegates {
			if isValid {
				//Block was valid, but voted invalid
				if validationResults[validator.Address] == false {
					validator.reputation *= 0.5
				} else {
					validator.reputation = math.Min(100, 1+validator.reputation)
				}
			} else {
				//Block invalid, but voted valid
				if validationResults[validator.Address] == true {
					validator.reputation *= 0.5
				} else {
					validator.reputation = math.Min(100, 1+validator.reputation)
				}
			}
		}

		printInfo()
		return
	}

	//short range attack
	if currAttack == "network_partition" && evilProposer {
		isValid := validCount >= len(delegates)/2
		isValidTwo := validTwoCount >= len(delegates)/2

		if isValid {
			//broadcast the verified transactions to all blocks within proposer's group
			println("Valid block added to blockchain")
			proposer.blockSuccessCount += 1
			proposer.reputation = math.Min(100, proposer.reputation+1)
			//broadcast the verified transactions to all blocks
			for _, validator := range validators {
				if slices.Contains(ForkedBlockchain[proposerGroup], validator) {
					msg := VerifiedBlockMessage{
						transactions: newBlock.Transactions,
						newBlock:     newBlock,
					}
					validator.incomingChannel <- msg
				}
			}

			//Update transactional amounts and reward proposer
			for _, transaction := range newBlock.Transactions {
				transaction.Sender.Balance -= (transaction.Amount + transaction.Reward)
				transaction.Receiver.Balance += transaction.Amount
				proposer.Stake += transaction.Reward

				senderString := fmt.Sprintf("New balance: %f\n", transaction.Sender.Balance)
				io.WriteString(transaction.Sender.conn, senderString)

				receiverString := fmt.Sprintf("New balance: %f\n", transaction.Receiver.Balance)
				io.WriteString(transaction.Receiver.conn, receiverString)
			}
		} else {
			println("Committee votes block invalid")
			proposer.reputation *= 0.2
		}
		if isValidTwo {
			println("Valid block added to blockchain")
			proposer.blockSuccessCount += 1
			proposer.reputation = math.Min(100, proposer.reputation+1)
			//broadcast the verified transactions to all blocks not witihin proposer's group
			for _, validator := range validators {
				if !slices.Contains(ForkedBlockchain[proposerGroup], validator) {
					msg := VerifiedShortAttackBlockTwoMessage{
						transactions: newBlockTwo.Transactions,
						newBlockTwo:  newBlockTwo,
					}
					validator.incomingChannel <- msg
				}
			}

			//Update transactional amounts and reward proposer
			for _, transaction := range newBlockTwo.Transactions {
				transaction.Sender.Balance -= (transaction.Amount + transaction.Reward)
				transaction.Receiver.Balance += transaction.Amount
				proposer.Stake += transaction.Reward

				senderString := fmt.Sprintf("New balance: %f\n", transaction.Sender.Balance)
				io.WriteString(transaction.Sender.conn, senderString)

				receiverString := fmt.Sprintf("New balance: %f\n", transaction.Receiver.Balance)
				io.WriteString(transaction.Receiver.conn, receiverString)
			}
			println("Valid block added to blockchain")
		} else {
			println("Committee votes block invalid")
			proposer.reputation *= 0.2
		}
		if isValid && isValidTwo {
			forked = true
			forkProposer = proposer
		}
		printInfo()
		return
	}

	//add block if majority believe block is valid
	isValid := validCount >= len(delegates)/2
	if isValid {
		println("Valid block added to blockchain")
		proposer.blockSuccessCount += 1
		proposer.reputation = math.Min(100, proposer.reputation+1)
		//broadcast the verified transactions to all blocks
		msg := VerifiedBlockMessage{
			transactions: newBlock.Transactions,
			newBlock:     newBlock,
		}
		for _, validator := range validators {
			validator.incomingChannel <- msg
		}

		//Update transactional amounts and reward proposer
		for _, transaction := range newBlock.Transactions {
			transaction.Sender.Balance -= (transaction.Amount + transaction.Reward)
			transaction.Receiver.Balance += transaction.Amount
			proposer.Stake += transaction.Reward

			senderString := fmt.Sprintf("New balance: %f\n", transaction.Sender.Balance)
			io.WriteString(transaction.Sender.conn, senderString)

			receiverString := fmt.Sprintf("New balance: %f\n", transaction.Receiver.Balance)
			io.WriteString(transaction.Receiver.conn, receiverString)
		}
	} else {
		println("Committee votes block invalid")
		proposer.reputation *= 0.2
	}
	//punish validators who voted against the majority
	for _, validator := range delegates {
		if isValid {
			//Block was valid, but voted invalid
			if validationResults[validator.Address] == false {
				validator.reputation *= 0.5
			} else {
				validator.reputation = math.Min(100, 1+validator.reputation)
			}
		} else {
			//Block invalid, but voted valid
			if validationResults[validator.Address] == true {
				validator.reputation *= 0.5
			} else {
				validator.reputation = math.Min(100, 1+validator.reputation)
			}
		}
	}

	printInfo()

}

func handleConnection(conn net.Conn, runType string, connectionType string, malString string, splitView bool) {
	defer conn.Close()

	//Determine user or validator connection
	io.WriteString(conn, "Is this node a user or validator (u/v)\n")
	scannedType := bufio.NewScanner(conn)
	if runType == "auto" {
		scannedType = bufio.NewScanner(strings.NewReader(connectionType))
	}
	for scannedType.Scan() {
		if scannedType.Text() == "u" {
			handleUserConnection(conn, runType)
		} else if scannedType.Text() == "v" {
			handleValidatorConnection(conn, runType, malString, splitView)
		} else {
			fmt.Printf("%s is not a valid response\n Please enter 'u' or 'v' ", scannedType.Text())
		}
		break
	}
}
