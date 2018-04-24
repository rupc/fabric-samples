package main

import (
    // "math"
    // "math/big"
    // "crypto/rand"
    // "crypto/hmac"
    // "encoding/binary"
    // "encoding/hex"
    "math/rand"
    // "bufio"
    // "os"
    // "net/http"
    "strings"
    // "io/ioutil"
    // "github.com/tidwall/gjson"
    // gostat "github.com/ematvey/gostat"
    // "crypto/md5"
    // "encoding/binary"
    "time"
    // "sort"
    // "sync"
    "strconv"
    "crypto/sha256"
    "fmt"
    "encoding/json"
    "github.com/hyperledger/fabric/core/chaincode/shim"
    pb "github.com/hyperledger/fabric/protos/peer"

)

var logger = shim.NewLogger("CLDChaincode")
const (
    REGISTERED = 1
    DUED = 2
    ANNOUNCED = 3
    CHECKED = 4
    MAX_EVENTS  = 10
)

type lottery_event struct {
    Status         string `json:Status`
    EventName       string `json:EventName`
    IssueDate       string `json:IssueDate`
	Duedate         string	`json:"Duedate"`  // UNIX timestamp
	AnnouncementDate string	`json:"AnnouncementDate"`  // UNIX timestamp
	NumOfMembers    string	`json:"NumOfMembers"`
	NumOfWinners    string	`json:"NumOfWinners"`
	MemberList      string	`json:"MemberList"` // Comma seperated member list
    RandomKey       string `json:"RandomKey"` // This is from input, so it's not non-deterministic
    InputHash       string `json:"InputHash"` // built from eventname, duedate, num of members, winners and member list, randomkey from server
    FutureBlockHeight string `json:"FutureBlockHeight"`
    WinnerList      string `json:"WinnerList"` // comma seperated winner list
    Script          string `json:"Script"` // script text for determine_winner()
    VerifiableRandomkey string `json:"VerifiableRandomkey"`
}

func (l lottery_event) GetAllConcats() string {
    var allConCats string = ""
    allConCats = l.EventName + l.IssueDate + l.Duedate + l.AnnouncementDate + l.NumOfMembers + l.NumOfWinners + l.MemberList + l.RandomKey + l.InputHash + l.FutureBlockHeight + l.WinnerList + l.Script
    return allConCats
}

// Do sha256 all concatenated strings
func (l lottery_event) GetVerifiableRandomKeyfromLottery() string {
    var allConCats = l.GetAllConcats()
    h := sha256.New()
    h.Write([]byte(allConCats))
    return fmt.Sprintf("%x", h.Sum(nil))
}

type SimpleChaincode struct {

}

func (t *SimpleChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response  {
    // Inititial data needed for testing
	fmt.Println("Lottery chaincode(named lottery_cc) Init method called!!!")

    sampleRegistered := lottery_event {
        Status: "REGISTERED",
        InputHash: "6b60d2b794860dc84148f44d479fd7c634eaf8e3396e723d5d2224c98f38f5d1",
        EventName: "test-event1",
        IssueDate: "1495701618",
        Duedate: "1511098413",
        AnnouncementDate: "1511198413",
        FutureBlockHeight: "400000",
        NumOfMembers: "7",
        NumOfWinners: "3",
        RandomKey: "241218793433130254621482405472826812551",
        VerifiableRandomkey: "UNDEFINED" ,
        MemberList: "a,b,c,d,e,f,g",
        WinnerList: "UNDEFINED",
        Script: "sampleRegistered script1",
    }

    sampleEnded := lottery_event {
        Status: "REGISTERED",
        InputHash: "435df910d961f25d051a71e1daeed210cb43c31b4e92bf241a7a044bdebe50a5",
        EventName: "Edible-Secretary",
        IssueDate: "1498601618",
        Duedate: "1510088413",
        AnnouncementDate: "1511188413",
        FutureBlockHeight: "300000",
        NumOfMembers: "4",
        NumOfWinners: "2",
        RandomKey: "26047126683174221326655007522109018381",
        VerifiableRandomkey: "UNDEFINED" ,
        MemberList: "t1,t2,t3,t4",
        WinnerList: "UNDEFINED",
        Script: "sampleEnded script1",
    }

    sampleCheck := lottery_event {
        Status: "ANNOUNCED",
        InputHash: "e284211d3c91622692531bfd860a438d21ee6a04a2f941c970d30b5bab214a30",
        EventName: "event-checkNverify",
        IssueDate: "1497076380", // 2017년 5월 10일 토요일 오후 3:33:00 GMT+09:00
        Duedate: "1497508380", // 2017년 5월 15일 목요일 오후 3:33:00 GMT+09:00
        AnnouncementDate: "1498804200", // 2017년 5월 30일 금요일 오후 3:30:00
        FutureBlockHeight: "473530",
        NumOfMembers: "5",
        NumOfWinners: "2",
        RandomKey: "45432542334432543212154312",
        VerifiableRandomkey: "UNDEFINED" ,
        MemberList: `zQcVvDw3GnCtLlE7kGaJh+DIywBPSeWAIvwcqqZLPGw,
                    3vp/4SY25oVCWmZys0ON84fzBoE8xhWFYEQ//QLwqYU=,
                    RneBijcu1uMeNgPjmJcEf/FYUos/BUcPnHQt/M7+Nhg=,
                    GFlVlk0WHnBUqbGBRJpi+Smb71iWNKwCVkzHAUuyKqo=,
                    y6ifF4M2s3szUOu/gai4VGa8jbLQEbq0UPgce8ZqD6o=,`,
        WinnerList: "UNDEFINED",
        Script: `
        func do_determine_winner(le lottery_event) []int {
            // var im InputManifest = convert_lottery_to_im(le)
            // print_im(im)
            var block Block
            var winner_list []int
            var block_hash string

            if le.FutureBlockHeight == "UNDEFINED" {
                fmt.Printf("FutureBlockHeight is UNDEFINED\nGetting latest block...\n")
                block = get_latest_block()
                block_hash = block.hash
            }

            if le.InputHash == "UNDEFINED" {
                fmt.Printf("InputHash or FutureBlockHeight is missing\n")
                return nil
            }

            random_key, _ := strconv.ParseUint(le.RandomKey, 10, 64)
            random_key_bit_array := gen_random_bit_array(random_key)

            // block = get_block_by_height(om.future_blk_height)
            // test latestblock hash first
            block = get_latest_block()
            block_hash = block.hash

            if block.hash == "" {
                panic("Future block not published\nShutting down program")
            }

            sig := hmac.New(sha256.New, []byte(random_key_bit_array))
            sig.Write([]byte(block_hash))

            // random bits is built from random key
            random_bits := hex.EncodeToString(sig.Sum(nil))

            fmt.Printf("random bits from hmac: %s\n", random_bits)

            num_winners, _ := strconv.Atoi(le.NumOfWinners)
            num_members, _ := strconv.Atoi(le.NumOfMembers)

            //
            var concat string = ""
            var lucky_map map[int]string
            lucky_map = make(map[int]string)

            for idx := 0; idx < num_members; idx++ {
                concat = random_bits + "" + strconv.Itoa(idx)

                hash := sha256.New()
                hash.Write([]byte(concat))
                index_hash := fmt.Sprintf("%x", hash.Sum(nil))

                lucky_map[idx] = index_hash
            }

            // Sort by value. References follwing link
            // http://ispycode.com/GO/Sorting/Sort-map-by-value
            hack := make(map[string]int)
            hackkeys := []string{}

            for key, val := range lucky_map {
                hack[val]=key
                hackkeys = append(hackkeys, val)
            }
            sort.Strings(hackkeys)

            // print winners
            for i := 0; i < num_winners; i++ {
                fmt.Printf("%dth: %s\n", hack[hackkeys[i]], hackkeys[i])
                winner_list = append(winner_list, hack[hackkeys[i]])
            }

            return winner_list
        }`,
    }

    jsonBytes, err := json.Marshal(sampleRegistered)
    err = stub.PutState(sampleRegistered.InputHash, jsonBytes)
    jsonBytes, err = json.Marshal(sampleEnded)
    err = stub.PutState(sampleEnded.InputHash, jsonBytes)
    jsonBytes, err = json.Marshal(sampleCheck)
    err = stub.PutState(sampleCheck.InputHash, jsonBytes)
    if err != nil {
        return shim.Error("lottery event Marshaling fails")
    }

    /* numOfEvents := make([]byte, 1)
    numOfEvents[0] = 2
    err = stub.PutState("numOfEvents", numOfEvents)
    fmt.Printf("Number of lottery event: %d\n", numOfEvents) */


	return shim.Success(nil)
}

/* func debug() {
    test_networkaccess()
} */


func (t *SimpleChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	fmt.Println("Blockchain Lottery Chaincode! invoke method###")
	function, args := stub.GetFunctionAndParameters()
	fmt.Println("Invoked method is "+args[0])

	if function != "invoke" {
        return shim.Error("Unknown function call: " + function)
    }

	if args[0] == "create_lottery_event" {
		return t.create_lottery_event(stub, args)
	}

    if args[0] == "create_lottery_event_hash" {
        return t.create_lottery_event_hash(stub, args)
    }

    if args[0] == "query_lottery_event_hash" {
        return t.query_lottery_event_hash(stub, args)
    }

	if args[0] == "query_lottery_event" {
		return t.query_lottery_event(stub, args)
	}

	if args[0] == "create_target_block" {
		return t.create_target_block(stub, args)
	}

	if args[0] == "query_target_block" {
		return t.query_target_block(stub, args)
	}

	if args[0] == "determine_winner" {
		return t.determine_winner(stub, args)
	}

	if args[0] == "query_checkif_winner" {
		return t.query_checkif_winner(stub, args)
	}

	if args[0] == "query_winner" {
		return t.query_winner(stub, args)
	}

	if args[0] == "query_all_lottery_event_hash" {
		return t.query_all_lottery_event_hash(stub, args)
	}

	if args[0] == "subscribe" {
		// Creates a complete purchase order from its state
		return t.subscribe(stub, args)
	}

	if args[0] == "close_event" {
		// Creates a complete purchase order from its state
		return t.close_event(stub, args)
	}

	if args[0] == "check" {
		// check is another name of determine_winner
		return t.determine_winner(stub, args)
	}

    if args[0] == "verify" {
        return t.verify_result(stub, args)
    }

    if args[0] == "test_networkaccess" {
        return t.test_networkaccess(stub, args)
    }

    if args[0] == "testRandomnessDifferentKeys" {
        return t.test_randomness(stub, args)
    }

    if args[0] == "testRandomnessDifferentKeys" {
        return t.testRandomnessDifferentKeys(stub, args)
    }

	return shim.Error("Unknown Invoke Method")
}

// create_lottery_event_hash use manifest hash as search key
// arg0: function name
// arg1: manifest hash
// arg2: event name
// arg3: issue date/time, unixtime stamp, not milisecond
// arg4: due date/time, unixtime stamp, not milisecond
// arg5: announcement date/time, unixtime stamp, not milisecond
// arg6: future block number
// arg7: number of members
// arg8: number of winners
// arg9: random key
// arg10: script
// TODO: arg11 would be list of presents 
func (t *SimpleChaincode) create_lottery_event_hash(stub shim.ChaincodeStubInterface, args []string) pb.Response {
    fmt.Println("Invoke - create_lottery_event_hash")
    const numOfArgs = 11
    if len(args) != numOfArgs {
        return shim.Error("Incorrect number of arguments. Expecting 11 including function name");
    }

    for idx, val := range(args) {
        fmt.Printf("args[%d]: s%\n", idx, val)
    }

    already, _ := stub.GetState(args[1])
    if len(already) != 0 {
       return shim.Error("Same manifest hash error, use different manifest hash to register event")
    }

    le := lottery_event {
        Status: "REGISTERED",
        InputHash: args[1],
        EventName: args[2],
        IssueDate: args[3],
        Duedate: args[4],
        AnnouncementDate: args[5],
        FutureBlockHeight: args[6],
        NumOfMembers: args[7],
        NumOfWinners: args[8],
        RandomKey: args[9],
        MemberList: "UNDEFINED",
        WinnerList: "UNDEFINED",
        Script: args[10],
    }

    jsonBytes, err := json.Marshal(le)
    if err != nil {
        return shim.Error("lottery event Marshaling fails")
    }

    fmt.Printf("%v\n", le)

    // Insert a lottery event
    err = stub.PutState(le.InputHash, jsonBytes)

    // Update event count: might be useless
    /* var numOfEvents int
    numOfEventsJsonBytes, _ := stub.GetState("numOfEvents")
    if numOfEventsJsonBytes == nil {
        fmt.Printf("Event count is 0, first event created\n")
        numOfEvents = 0
    }
    err = json.Unmarshal(numOfEventsJsonBytes, &numOfEvents)
    numOfEvents++;
    numOfEventsJsonBytes, _ = json.Marshal(numOfEvents)
    err = stub.PutState("numOfEvents", numOfEventsJsonBytes)
    fmt.Printf("Number of lottery event: %d\n", numOfEvents)

    // Add a new event to new list
    var events [MAX_EVENTS]lottery_event // needed to update later to dynamically adjust it
    // events := make([]lottery_event,)
    eventsJsonBytes, _ := stub.GetState("events")
    if eventsJsonBytes == nil {
        fmt.Printf("Added to event list for the first time")
    }
    err = json.Unmarshal(eventsJsonBytes, &events)
    events[len(events) - 1] = le
    eventsJsonBytes, err = json.Marshal(events)
    err = stub.PutState("events", eventsJsonBytes)
    fmt.Printf("Added to event list") */


    if err != nil {
        return shim.Error(err.Error())
    }

    return shim.Success(nil)
}

func GetStateInt(stub shim.ChaincodeStubInterface, key string) int {
    var i int
    jsonbytes, err := stub.GetState(key)
    if jsonbytes == nil {
        return -1
    }
    json.Unmarshal(jsonbytes, &i)
    if err != nil {
        return -1
    }
    return i
}

func GetEventListsBytes(stub shim.ChaincodeStubInterface) []byte {
    var events [MAX_EVENTS]lottery_event // needed to update later to dynamically adjust it
    jsonbytes, err := stub.GetState("events")

    json.Unmarshal(jsonbytes, &events)
    fmt.Printf("%v\n", events)
    if err != nil {
        return nil
    }

    return jsonbytes
}

func (t *SimpleChaincode) query_lottery_event_hash(stub shim.ChaincodeStubInterface, args []string) pb.Response {
    fmt.Println("Invoke - query_lottery_event_hash")
    const numOfArgs = 2
    if len(args) != numOfArgs {
        return shim.Error("Incorrect number of arguments. Expecting 2 including function name");
    }
    fmt.Println("Given manifest hash(args[1]): " + args[1])
    jsonbytes, err := stub.GetState(args[1])

    fmt.Println(jsonbytes);
    if jsonbytes == nil {
        return shim.Error("No event has that name: " + args[1]);
    }
    if err != nil {
        return shim.Error("Unable to get lottery event")
    }
    var le lottery_event
    err = json.Unmarshal(jsonbytes, &le)
    if err != nil {
        return shim.Error("Unmarshaling lottery event fails")
    }

    fmt.Printf("%v\n", le)
    return shim.Success(jsonbytes)
}

// 7 args: function name, event name, Duedate, # of members, # of winner, comma seperated member list, random key.. but it could be one with long json string
// Input validation check must be done at server or user
func (t *SimpleChaincode) create_lottery_event(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	fmt.Println("Invoke - create_lottery_event")
    fmt.Printf("args[1]:%s\nargs[2]:%s\nargs[3]:%s\nargs[4]:%s\nargs[5]:%s", args[1], args[2], args[3], args[4], args[5], args[6])

    const numOfArgs = 7
    if len(args) != numOfArgs {
        return shim.Error("Incorrect number of arguments. Expecting 7 including function name");
    }

    AlreadyBytes, _ := stub.GetState(args[1])
    if len(AlreadyBytes) != 0 {
       return shim.Error("Already registered event, please set different name for differnet event")
    }

    le := lottery_event {
        EventName: args[1],
        Duedate: args[2],
        NumOfMembers: args[3],
        NumOfWinners: args[4],
        RandomKey: args[5],
        MemberList: args[6],
        InputHash: "UNDEFINED",
        FutureBlockHeight: "UNDEFINED",
        WinnerList: "UNDEFINED",
    }

    var all_concats string
    for i := 1; i < numOfArgs; i++{
        all_concats += args[i];
    }

    // Can't utilize random functions in chaincode itself(ex. cryptographic secure random generator or gamma_func)
    // Because if it does, each peer will have different hash value
    // So, It only depends on inputs provided. Input(server or user) should provide random key
    hash := sha256.New()
    hash.Write([]byte(all_concats))
    index_hash := fmt.Sprintf("%x", hash.Sum(nil))
    le.InputHash = index_hash; // Input hash can be used as key

    jsonBytes, err := json.Marshal(le)
    if err != nil {
        return shim.Error("lottery event Marshaling fails")
    }
    // print processed input
    // fmt.Println(string(le))
    fmt.Printf("%v\n", le)

    err = stub.PutState(le.EventName, jsonBytes);
    // or hash as key, which it is more suitable approach
    // err = stub.PutState(le.InputHash, jsonBytes);

    if err != nil {
        return shim.Error(err.Error())
    }

    return shim.Success([]byte(index_hash))
}

// 1 args : Lottery event hash 
func (t *SimpleChaincode) query_lottery_event(stub shim.ChaincodeStubInterface, args []string) pb.Response {
    fmt.Println("Invoke: query_lottery_event")
    fmt.Println("args[1] is " + args[1])
    jsonbytes, err := stub.GetState(args[1])

    fmt.Println(jsonbytes);
    if jsonbytes == nil {
        return shim.Error("No event has that name: " + args[1]);
    }
    if err != nil {
        return shim.Error("Unable to get lottery event")
    }
    var le lottery_event
    err = json.Unmarshal(jsonbytes, &le)
    if err != nil {
        return shim.Error("Unmarshaling lottery event fails")
    }
    fmt.Printf("Eventname:%s\nInputHash: %s\n", le.EventName, le.InputHash)
    return shim.Success(jsonbytes)
}

func (t *SimpleChaincode) chaincode_randomized(stub shim.ChaincodeStubInterface, args []string) pb.Response {

    return shim.Success(nil)
}

/**
* @brief 
*
* @param arg1: Input hash: used for getting a lottery event
* @return Future Block Height
*/
func (t *SimpleChaincode) create_target_block(stub shim.ChaincodeStubInterface, args []string) pb.Response {
    fmt.Println("chaincode: create_target_block invoked")
    const numOfArgs = 2
    if len(args) != 2 {
        return shim.Error("Incorrect number of arguments. Expecting 2 including function name, Input hash");
    }
    fmt.Println("create_target_block: args[1] is " + args[1])

    // Currently search key is the event name for easy development
    var search_key string = args[1]

    jsonbytes, err := stub.GetState(search_key)
    if jsonbytes == nil {
        return shim.Error("No event has that name: " + args[1]);
    }
    if err != nil {
        return shim.Error("Unable to get lottery event from input hash")
    }

    // Get lottery event from inupt hash as a key
    var le lottery_event
    err = json.Unmarshal(jsonbytes, &le)

    if err != nil {
        return shim.Error("Unmarshaling lottery event fails in create_target_block")
    }

    // Actually getting future target block
    le.FutureBlockHeight = do_create_target_block(le)
    fmt.Printf("FutureBlockHeight: %s\n", le.FutureBlockHeight)

    jsonBytes, err := json.Marshal(le)
    if err != nil {
        return shim.Error("lottery event Marshaling fails")
    }

    err = stub.PutState(le.EventName, jsonBytes);
    // err = stub.PutState(le.search_key, jsonBytes);
    if err != nil {
        return shim.Error(err.Error())
    }

    return shim.Success([]byte(le.FutureBlockHeight))
}

func (t *SimpleChaincode) query_target_block(stub shim.ChaincodeStubInterface, args []string) pb.Response {
    // Currently, arg[1] is event name, it will be hash
    fmt.Println("Invoke: query_target_block")
    jsonbytes, err := stub.GetState(args[1])
    if err != nil {
        return shim.Error("Unable to get lottery event")
    }
    var le lottery_event
    err = json.Unmarshal(jsonbytes, &le)
    if err != nil {
        return shim.Error("Unmarshaling lottery event fails")
    }
    fmt.Printf("Future Target Block height: %s\n", le.FutureBlockHeight)
    return shim.Success([]byte(le.FutureBlockHeight))
}

// args: (0: function_name, 1: Manifest Hash, 2: verifiableRandomkey)
// args2 is 128 random bits array, 4 32-bit value concatenated by commna
func (t *SimpleChaincode) determine_winner(stub shim.ChaincodeStubInterface, args []string) pb.Response {
    fmt.Println("ChainCode: determine_winner invoked")
    const numOfArgs = 3
    if len(args) != numOfArgs {
        return shim.Error("Incorrect number of arguments. Expecting 3 including function name, manifest hash, random key");
    }
    fmt.Println("args[0]: " + args[0])
    fmt.Println("args[1]: " + args[1])
    fmt.Println("args[2]: " + args[2])

    // Currently, search key is the event name for easy development NO!
    // Search key is manifest hash, not event name
    var search_key string = args[1]
    // var vkey string = args[2]

    jsonbytes, err := stub.GetState(search_key)
    if jsonbytes == nil {
        return shim.Error("No event has that name: " + args[1]);
    }

    if err != nil {
        return shim.Error("Unable to get lottery event from search key")
    }

    // Get lottery event from inupt hash as a key
    var le lottery_event
    err = json.Unmarshal(jsonbytes, &le)

    if err != nil {
        return shim.Error("Unmarshaling lottery event fails in determine_winner")
    }

    // Check if the this operation is already done
    if le.Status == "CHECKED" {
        fmt.Println("Check operation is not the first time!", "Just returning winner list")
        return shim.Success([]byte(le.WinnerList))
    }

    // Get the actual winner list
    winner_list, winner_listNames, nonce := do_determine_winner(le)
    encryptedMemberList := strings.Split(le.MemberList, ",")
    fmt.Printf("winner_listNames: %s\n", winner_listNames)
    fmt.Printf("encryptedMemberList: %s\n", encryptedMemberList)
    fmt.Printf("nonce: %s\n", nonce)
    var winner_list_names []string

    for i := 0; i < len(winner_list); i++ {
        winner_list_names = append(winner_list_names, encryptedMemberList[winner_list[i]])
    }

    var winner_concat string
    winner_concat = strings.Join(winner_list_names[:],",")

    // Not necessary condition lol
    /* if le.WinnerList != "UNDEFINED" {
        fmt.Printf("Check operation is the first time!\n")
    } */

    if le.Status == "CHECKED" {
        fmt.Printf("Check operation is not the first time!\n")
    }

    fmt.Printf("Before asigning WinnerList%v\n", le)
    le.WinnerList = winner_concat
    fmt.Printf("After asigning WinnerList%v\n", le)

    /* fmt.Printf("Winners: %s\n", winner_concat) */
    logger.Info("Winners: %s\n", winner_concat)

    // We will check VerifiableRandomkey is consistent when verifying the result
    le.VerifiableRandomkey = getVerifiableRandomKey(le) + le.GetVerifiableRandomKeyfromLottery();
    logger.Info("VerifiableRandomkey %s", le.VerifiableRandomkey)
    le.Status = "CHECKED"
    jsonBytes, err := json.Marshal(le)
    if err != nil {
        return shim.Error("lottery event Marshaling fails")
    }


    err = stub.PutState(le.InputHash, jsonBytes);
    // err = stub.PutState(le.EventName, jsonBytes);
    // err = stub.PutState(le.search_key, jsonBytes);
    if err != nil {
        return shim.Error(err.Error())
    }

    return shim.Success([]byte(winner_concat))
}

func (t *SimpleChaincode) verify_result(stub shim.ChaincodeStubInterface, args []string) pb.Response {
    fmt.Println("ChainCode: verify_result invoked")
    const numOfArgs = 2
    var res string = "true"
    if len(args) != numOfArgs {
        return shim.Error("Incorrect number of arguments. Expecting 2 including function name, manifest hash");
    }
    fmt.Println("args[0]: " + args[0])
    fmt.Println("args[1]: " + args[1])

    // Manifest hash
    var search_key string = args[1]

    // Get lottery information using manifest hash
    jsonbytes, err := stub.GetState(search_key)
    if jsonbytes == nil {
        return shim.Error("No event has that name: " + args[1]);
    }

    if err != nil {
        return shim.Error("Unable to get lottery event from search key")
    }

    // Get lottery event from inupt hash as a key
    var le lottery_event
    err = json.Unmarshal(jsonbytes, &le)

    if err != nil {
        return shim.Error("Unmarshaling lottery event fails in determine_winner")
    }

    if le.Status != "CHECKED" {
        return shim.Error("Verifying the result is only possible when the result is available")
    }

    if le.VerifiableRandomkey == (getVerifiableRandomKey(le) + le.GetVerifiableRandomKeyfromLottery()) {
        logger.Info("Verifying successfully")
        res = "success"
    } else {
        logger.Info("Verifying unsuccessfully")
        res = "fail"
    }

    return shim.Success([]byte(res))
}

func (t *SimpleChaincode) query_checkif_winner(stub shim.ChaincodeStubInterface, args []string) pb.Response {

    return shim.Success(nil)

}

func (t *SimpleChaincode) query_winner(stub shim.ChaincodeStubInterface, args []string) pb.Response {
    // Currently, arg[1] is event name, it will be hash
    fmt.Println("Invoke: query_winner")
    jsonbytes, err := stub.GetState(args[1])
    if err != nil {
        return shim.Error("Unable to get lottery event")
    }
    var le lottery_event
    err = json.Unmarshal(jsonbytes, &le)
    if err != nil {
        return shim.Error("Unmarshaling lottery event fails")
    }
    fmt.Printf("Winner(s): %s\n", le.WinnerList)
    return shim.Success([]byte(le.WinnerList))
}

func (t *SimpleChaincode) Query(stub shim.ChaincodeStubInterface) pb.Response {

	return shim.Error("Query has been implemented in invoke")
}

func (t *SimpleChaincode) test_randomness(stub shim.ChaincodeStubInterface, args []string) pb.Response {
    fmt.Println("Test randomness")
    s1 := rand.NewSource(time.Now().UnixNano())
    r1 := rand.New(s1)

    sameKey := "samekey"
    arbitaryVal1 := r1.Intn(1000)
    arbitaryVal2 := r1.Intn(1000)

    fmt.Printf("Generated two random values: %d %d\n", arbitaryVal1, arbitaryVal2)
    fmt.Println("Check non-determinism in Hyperledger/Fabric")
    fmt.Println("test: Same key with different values")
    stub.PutState(sameKey, []byte(strconv.Itoa(arbitaryVal1)))
    stub.PutState(sameKey, []byte(strconv.Itoa(arbitaryVal2)))

	return shim.Success(nil)
}

func (t *SimpleChaincode) testRandomnessDifferentKeys(stub shim.ChaincodeStubInterface, args []string) pb.Response {
    fmt.Println("Test randomness")
    s1 := rand.NewSource(time.Now().UnixNano())
    r1 := rand.New(s1)
    sameValue := []byte{1,2,3,4,5}

    arbitaryKey1 := r1.Intn(1000)
    arbitaryKey2 := r1.Intn(1000)

    fmt.Printf("Generated two random keys: %d %d\n", arbitaryKey1, arbitaryKey2)
    fmt.Println("Check non-determinism in Hyperledger/Fabric")
    fmt.Println("test: Differenet key with same values")

    stub.PutState(strconv.Itoa(arbitaryKey1), sameValue)
    stub.PutState(strconv.Itoa(arbitaryKey2), sameValue)

	return shim.Success(nil)
}

// Possible
func (t *SimpleChaincode) test_networkaccess(stub shim.ChaincodeStubInterface, args []string) pb.Response {
    block := get_latest_block()
    jsonBytes, err := json.Marshal(block)

    fmt.Printf("%s\n", string(jsonBytes))

    if err != nil {
        return shim.Error("Error getting Latest Block")
	}
    return shim.Success(jsonBytes)
}


func main() {
	err := shim.Start(new(SimpleChaincode))
	if err != nil {
		fmt.Println("Error starting Chaincode: %s", err)
	}
}
