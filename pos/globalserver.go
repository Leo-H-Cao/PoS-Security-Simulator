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
	"gonum.org/v1/gonum/stat/sampleuv"
)

// Blockchain is a series of validated Blocks
var CertifiedBlockchain []Block
var balanceBlockchain [][]Block

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

var delegateCounter = 0

func Run(runType string, numValidators int, numUsers int, numMal int, comSize int, delSize int, blockchainType string, attack string) {
	err := godotenv.Load()
	if err != nil {
		log.Fatal(err)
	}
	committeeSize = comSize
	delegateSize = delSize
	delegateCounter = 2 * delegateSize

	if attack == "balance"{
		// create genesis block
		t := time.Now()
		genesisBlock0 := Block{}
		genesisBlock0 = Block{Index: 0, Timestamp: t.String(), Transactions: []Transaction{}, Hash: calculateBlockHash(genesisBlock0), PrevHash: "", Validator: ""}
		genesisBlockchain0 := []Block{genesisBlock0}
		balanceBlockchain = append(balanceBlockchain, genesisBlockchain0)

		// create fork in blockchain for balance attack
		genesisBlock1 := Block{}
		genesisBlock1 = Block{Index: 1, Timestamp: t.String(), Transactions: []Transaction{}, Hash: calculateBlockHash(genesisBlock1), PrevHash: "", Validator: ""}
		genesisBlockchain1 := []Block{genesisBlock1}
		balanceBlockchain = append(balanceBlockchain, genesisBlockchain1)
	} else{
		t := time.Now()
		genesisBlock := Block{}
		genesisBlock = Block{Index: 0, Timestamp: t.String(), Transactions: []Transaction{}, Hash: calculateBlockHash(genesisBlock), PrevHash: "", Validator: ""}
		CertifiedBlockchain = append(CertifiedBlockchain, genesisBlock)
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
	if blockchainType == "pos" {
		go func() {
			for {
				nextTimeSlot()
			}
		}()
	} else if blockchainType == "reputation" {
		go func() {
			for {
				nextReputationTimeSlot()
			}
		}()
	} else {
		fmt.Println("Invalid blockchain type")
		return
	}

	//auto create connections
	go func() {
		if runType == "manual" {
			return
		}
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
			go handleConnection(conn, runType, "v", malString)
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
			go handleConnection(conn, runType, "u", "")
			numUsers--
		}
	}()

	//Accepts connections joining the network
	for {
		conn, err := server.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handleConnection(conn, runType, "", "")
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
		validator.reputation = math.Min(10, validator.reputation+1)
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

		msg := ConsensusMessage{
			blockchain:              CertifiedBlockchain,
			unconfirmedTransactions: unconfirmedTransactionsBuffer,
			confirmedTransactions:   confirmedTransactionsBuffer,
		}
		validator.incomingChannel <- msg
	}
}

func printInfo() {
	//prints blockchain
	// printString1 := ""
	// for _, block := range balanceBlockchain[0] {
	// 	printString1 += "->["
	// 	for _, transaction := range block.Transactions {
	// 		printString1 += fmt.Sprintf("%d,", transaction.ID)
	// 	}
	// 	printString1 = printString1[:len(printString1)-1]
	// 	printString1 += "]"
	// }

	// //build string for fork of blockchain
	// printString2 := ""
	// for _, block := range balanceBlockchain[1] {
	// 	printString2 += "->["
	// 	for _, transaction := range block.Transactions {
	// 		printString2 += fmt.Sprintf("%d,", transaction.ID)
	// 	}
	// 	printString2 = printString2[:len(printString2)-1]
	// 	printString2 += "]"
	// }

	// printString1 = printString1[1:]
	// printString2 = printString2[1:]
	// println("BLOCKCHAIN")
	// println(printString1)
	// println(printString2)

	//prints blockchain

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
	// println("Validator balances")
	// for _, validator := range validators {
	// 	fmt.Printf("%s: %f, %d\n", validator.Address[:3], validator.Stake, validator.committeeCount)
	// }

	//prints Validator reputation
	// println("Validator reputation")
	// for _, validator := range validators {
	// 	fmt.Printf("%s: %f\n", validator.Address[:3], validator.reputation)
	// }
}

func balanceAttackNextTimeSlot(){
	//wait 5 seconds every slot
	time.Sleep(5 * time.Second)
	fmt.Printf("\nTime slot %s\n\n", time.Now().Format("15:04:05"))

	//Choose a new block proposer based on stake
	validatorsSliceLock.Lock()
	if len(validators) == 0 {
		validatorsSliceLock.Unlock()
		return
	}
	validatorsCopy := validators
	validatorsSliceLock.Unlock()

	totalWeight := 0.0
	for _, validator := range validatorsCopy {
		totalWeight += validator.Stake
	}

	randomNumber := 0.0
	rand.Seed(time.Now().UnixNano())
	randomNumber = rand.Float64() * totalWeight

	weightSum := 0.0
	for _, validator := range validatorsCopy {
		weightSum += validator.Stake
		if weightSum >= randomNumber {
			proposer = validator
			break
		}
	}
	fmt.Printf("Proposer %s chosen as new block proposer\n", proposer.Address[:3])

	//divide the views of honest validators
	for i, validator := range validatorsCopy{
		if i <= len(validatorsCopy)/2{
			validator.blockchainView = 0
		}else{
			validator.blockchainView = 1
		}
	}

	//block proposer chooses a new block
	//different old blocks depending on view of blockchain
	oldBlock0 := balanceBlockchain[0][len(balanceBlockchain[0])-1]
	oldBlock1 := balanceBlockchain[1][len(balanceBlockchain[1])-1]
	newBlock, err := generateBlock(proposer)
	proposerChain := 0

	// set proposer chain view
	if !proposer.IsMalicious{
		proposerChain = proposer.blockchainView

		// generate new block for fork depending on proposer's view
		// if proposer.blockchainView == 1{
		// 	newBlock, err = generateBlock(oldBlock1, proposer)
		// }
	}

	// if proposer is malicious, generate for shorter chain
	// if proposer.IsMalicious && len(balanceBlockchain[1]) <= len(balanceBlockchain[0]){
	// 	newBlock, err = generateBlock(oldBlock1, proposer)
	// 	proposerChain = 1
	// } 

	
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Printf("Block %d chosen as new block\n", newBlock.Index)

	//randomly choose new committee of a third of all validators who will validate the new block
	rand.Shuffle(len(validatorsCopy), func(i, j int) {
		validatorsCopy[i], validatorsCopy[j] = validatorsCopy[j], validatorsCopy[i]
	})
	validationCommittee = validatorsCopy[:len(validatorsCopy)/3]
	fmt.Println("New validation committee chosen")

	//validation committee validates blocks
	//broadcast block to all members of committee
	for _, validator := range validationCommittee {
		oldBlock := Block{}
		if validator.blockchainView == 1{
			oldBlock = oldBlock1
		}else{
			oldBlock = oldBlock0
		}

		// send which fork is longer in message so malicious validator can manipulate and try to balance
		msg := ValidateBlockMessage{
			newBlock: newBlock,
			oldBlock: oldBlock,
			fork0Length: len(balanceBlockchain[0]),
			fork1Length: len(balanceBlockchain[1]),
			proposerView: proposerChain,
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
	fmt.Printf("Voting results\nInvalid Count: %d\nValid Count: %d\nCommittee size: %d\n", invalidCount, validCount, len(validationCommittee))

	//add block if majority believe block is valid
	isValid := validCount >= len(validationCommittee)/2
	if isValid {
		// append block depending on proposers view of fork
		if proposerChain == 1{
			balanceBlockchain[1] = append(balanceBlockchain[1], newBlock)
		} else{
			balanceBlockchain[0] = append(balanceBlockchain[0], newBlock)
		}
		println("Valid block added to blockchain")

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
	}
	//punish validators who voted against the majority
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

	printInfo()
}

func nextTimeSlot() {
	//wait 5 seconds every slot
	time.Sleep(5 * time.Second)
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

	// oldBlock := Blockchain[len(Blockchain)-1]
	newBlock, err := generateBlock(proposer)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Printf("Block %d chosen as new block\n", newBlock.Index)

	//validation committee validates blocks
	//broadcast block to all members of committee
	for _, validator := range validationCommittee {
		msg := ValidateBlockMessage{
			newBlock: newBlock,
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
		proposer.Stake *= 0.2
	}
	//punish validators who voted against the majority
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

	printInfo()


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

	newBlock, err := generateBlock(proposer)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Printf("Block %d chosen as new block\n", newBlock.Index)

	//validation committee validates blocks
	//broadcast block to all members of committee
	for _, validator := range delegates {
		msg := ValidateBlockMessage{
			newBlock: newBlock,
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
	// fmt.Printf("Voting results\nInvalid Count: %d\nValid Count: %d\nCommittee size: %d\n", invalidCount, validCount, len(validationCommittee))

	//add block if majority believe block is valid
	isValid := validCount >= len(validationCommittee)/2
	if isValid {
		println("Valid block added to blockchain")
		proposer.blockSuccessCount += 1
		proposer.reputation = math.Min(10, proposer.reputation+1)
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
		proposer.Stake *= 0.2
		proposer.reputation *= 0.2
	}
	//punish validators who voted against the majority
	slashPercentage := 0.8
	for _, validator := range delegates {
		if isValid {
			//Block was valid, but voted invalid
			if validationResults[validator.Address] == false {
				validator.Stake *= slashPercentage
				validator.reputation *= 0.2
			} else {
				validator.reputation = math.Min(10, 1+validator.reputation)
			}
		} else {
			//Block invalid, but voted valid
			if validationResults[validator.Address] == true {
				validator.Stake *= slashPercentage
				validator.reputation *= 0.2
			} else {
				validator.reputation = math.Min(10, 1+validator.reputation)
			}
		}
	}

	printInfo()

}

func handleConnection(conn net.Conn, runType string, connectionType string, malString string) {
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
			handleValidatorConnection(conn, runType, malString)
		} else {
			fmt.Printf("%s is not a valid response\n Please enter 'u' or 'v' ", scannedType.Text())
		}
		break
	}
}
