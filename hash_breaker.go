//
// TODOs:
//
// - Add more flags to allow the user to specify the range of characters to check
//

package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

const HASHRATE_UPDATE_INTERVAL = 300 * time.Millisecond

type Flags struct {
	Encryption string
	Log        bool
	Length     int
	Workers    int
}

// private function to register flags and parse them
func _registerFlags() Flags {
	lengthFlg := flag.Int("l", 4, "Length of the string to check")
	workersFlg := flag.Int("w", 8, "Number of workers to use")
	logFlg := flag.Bool("log", false, "Enable logging")

	encrFlag := flag.String("e", "sha256", "Encryption algorithm to use,\n valid options are: sha1, sha256, sha512, md5")

	// parse
	flag.Parse()

	return Flags{
		Encryption: *encrFlag,
		Length:     *lengthFlg,
		Workers:    *workersFlg,
		Log:        *logFlg,
	}
}

func _printHashRate(gs *GlobalState) {
	for {
		// if done, exit the goroutine
		if atomic.LoadInt32(&gs.Done) == 1 {
			fmt.Println()
			return
		}
		// sleep
		time.Sleep(HASHRATE_UPDATE_INTERVAL)

		// load the current hash count
		count := atomic.LoadInt64(&gs.HashCounter)
		rawCountPerSec := 1000 * float32(count) / float32(HASHRATE_UPDATE_INTERVAL.Milliseconds())
		countPerSec := rawCountPerSec
		// humanize rate
		var unit string
		if countPerSec > 1000000 {
			countPerSec /= 1000000
			unit = "M"
		} else if countPerSec > 1000 {
			countPerSec /= 1000
			unit = "K"
		}

		unit += "Hsh"

		// print the hash rate
		fmt.Printf("\r Working...\t(%6.2f%s/s)", countPerSec, unit)

		if gs.Flags.Log {
			str := fmt.Sprintf("%6.2f\n", rawCountPerSec)
			_, err := gs.LogFile.WriteString(str)
			if err != nil {
				fmt.Println("Error writing to log file:", err)
				return
			}

		}

		// reset the hash count
		atomic.StoreInt64(&gs.HashCounter, 0)
	}
}

// HashJob is a struct that contains the hash to be cracked, and
// the start and end of the range of characters to be checked
type HashJob struct {
	Start rune
}

type GlobalState struct {
	WaitGroup   *sync.WaitGroup
	TargetHash  *[]byte
	HashFunc    func([]byte) []byte
	Done        int32 // atomic bool
	HashCounter int64 // atomic int
	Flags       Flags
	LogFile     *os.File
}

// worker is a function that takes a channel of HashJobs and
// checks each character in the range of the HashJob, so between
// '0' and 'z' in this example
func worker(jobs <-chan HashJob, gs *GlobalState) {
	defer gs.WaitGroup.Done()

	for job := range jobs {
		testString := make([]rune, 1)
		testString[0] = job.Start

		// create a 'queue' of strings to work on
		queue := make([]string, 0)
		queue = append(queue, string(testString[:]))

		// loop until the queue is empty
		for len(queue) > 0 {
			// check if the done flag has been set
			if atomic.LoadInt32(&gs.Done) == 1 {
				return
			}

			// pop the first item off the queue
			str := queue[0]
			queue = queue[1:]

			// Check if string is already our max length
			if len(str) != gs.Flags.Length {
				// if not the same length, iterate through all possible characters
				// and add them to the queue
				for i := '0'; i < 'z'; i++ {
					queue = append(queue, str+string(i))
				}

			}
			h := gs.HashFunc([]byte(str))

			// increment the counter
			atomic.AddInt64(&gs.HashCounter, 1)

			// Check if we have a match
			if reflect.DeepEqual(h, *gs.TargetHash) {
				fmt.Println("\n✅ Found match:", str)
				atomic.StoreInt32(&gs.Done, 1)
				return
			}

		}
	}

}

func main() {
	// register flags
	flags := _registerFlags()

	// Check for non-flag argument
	if flag.NArg() != 1 {
		fmt.Println("Usage: hash_breaker <hex-hash>")
		flag.PrintDefaults()
		os.Exit(1)
		return
	}

	// decode the hex string
	hStr := flag.Arg(0)
	h, err := hex.DecodeString(hStr)
	if err != nil {
		fmt.Println("Error decoding hex string:", err)
		os.Exit(1)
		return
	}

	// Create a channel to receive jobs
	jobs := make(chan HashJob, 100)

	// Setup a wait group to wait for all workers to finish
	wg := sync.WaitGroup{}

	// Create a global state object to share between workers
	// and main thread
	var gs GlobalState
	gs.WaitGroup = &wg
	gs.TargetHash = &h
	gs.Done = 0
	gs.Flags = flags

	// if logging is enabled, create a file to log to
	if flags.Log {
		//get timestamp
		t := time.Now()
		timestamp := t.Format("2006-01-02-15-04-05")
		// get pwd
		pwd, err := os.Getwd()
		if err != nil {
			fmt.Println("Error getting pwd:", err)
			os.Exit(1)
			return
		}

		log_path := pwd + "/log-" + timestamp + ".txt"

		// create log file
		f, err := os.Create(log_path)
		if err != nil {
			fmt.Println("Error creating log file:", err)
			os.Exit(1)
			return
		}
		defer f.Close()
		gs.LogFile = f
	}

	// set the hassh function
	switch flags.Encryption {
	case "sha256": // sha256 func (default)
		gs.HashFunc = func(b []byte) []byte {
			hash := sha256.Sum256(b)
			return hash[:]
		}
	case "sha512": // sha512 func
		gs.HashFunc = func(b []byte) []byte {
			hash := sha512.Sum512(b)
			return hash[:]
		}
	case "md5": // md5 func
		gs.HashFunc = func(b []byte) []byte {
			hash := md5.Sum(b)
			return hash[:]
		}
	case "sha1": // sha1 func
		gs.HashFunc = func(b []byte) []byte {
			hash := sha1.Sum(b)
			return hash[:]
		}
	default: // invalid func
		fmt.Println("Invalid encryption algorithm:", flags.Encryption)
		os.Exit(1)
		return
	}

	// start workers
	for i := 0; i < flags.Workers; i++ {
		wg.Add(1)
		go worker(jobs, &gs)
	}

	for i := '0'; i < 'z'; i++ {
		jobs <- HashJob{i}
	}
	// close the jobs channel
	close(jobs)

	go _printHashRate(&gs)

	// wait for all workers to finish
	wg.Wait()

	if gs.Done == 0 {
		fmt.Println("❌ No match found, try increasing the length of the string to check (use -l flag)")
	}
}
