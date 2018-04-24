package main

import (
    "crypto/sha256"
    "crypto/hmac"
    "fmt"
    "sort"
    "encoding/hex"
    // "time"
    // gjson "./lib/tidwall/gjson"
    "strconv"
    // "strings"
    // "math"
)

// This function determins winner list
// Returns winner list, its encrypted version, nonce(might be used for verifiable randomkey)
func do_determine_winner(le lottery_event) ([]int, string, string) {
    // var im InputManifest = convert_lottery_to_im(le)
    // print_im(im)
    var block Block
    var winner_list []int
    var winner_listNames string = ""
    var block_hash string

    if le.FutureBlockHeight == "UNDEFINED" {
        fmt.Printf("FutureBlockHeight is UNDEFINED\nGetting latest block...\n")
        block = get_latest_block()
        block_hash = block.hash
    }

    if le.InputHash == "UNDEFINED" {
           fmt.Printf("InputHash or FutureBlockHeight is missing\n")
           return nil, "", ""
    }

    random_key, _ := strconv.ParseUint(le.RandomKey, 10, 64)
    random_key_bit_array := gen_random_bit_array(random_key)

    // FTB: Future Target Block
    FTB, _ := strconv.ParseInt(le.FutureBlockHeight,10,64)
    block = get_block_by_height(FTB)
    // test latestblock hash first
    // block = get_latest_block()
    block_hash = block.hash
    block_nonce := block.nonce
    fmt.Printf("Block Number: %d\n", FTB)
    fmt.Printf("Block hash: %s\n", block_hash)
    fmt.Printf("Block nonce: %s\n", block_nonce)

    if block.hash == "" {
        // Need to fixed
        panic("Future block not published\nShutting down program")
    }

    sig := hmac.New(sha256.New, []byte(random_key_bit_array))
    sig.Write([]byte(block_hash))

    // random bits is built from random key
    random_bits := hex.EncodeToString(sig.Sum(nil))

    fmt.Printf("random bits from hmac: %s\n", random_bits)

    num_winners, _ := strconv.Atoi(le.NumOfWinners)
    num_members, _ := strconv.Atoi(le.NumOfMembers)

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

        winner_listNames += hackkeys[i] + ","
    }
    return winner_list, winner_listNames, block_nonce
}

func gen_random_bit_array(random_key uint64) string {
    random_bits_str := strconv.FormatUint(random_key, 2)
    return random_bits_str
}

