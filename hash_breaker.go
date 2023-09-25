package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/pkg/profile"
)

// private function to register flags and parse them
func _registerFlags() Flags {

	profilerFlg := flag.Bool("profile", false, "Enable code profiling")
	lengthFlg := flag.Int("l", 4, "Length of the string to check")
	// add other flags ...

	// parse
	flag.Parse()

	return Flags{
		Profile: *profilerFlg,
		Length:  *lengthFlg,
	}
}

// HashJob is a struct that contains the hash to be cracked, and
// the start and end of the range of characters to be checked
type HashJob struct {
	Start rune
	Flags Flags
}

type GlobalState struct {
	WaitGroup  *sync.WaitGroup
	TargetHash *[]byte
	Done       int32 // atomic bool
}

type Flags struct {
	Profile bool
	Length  int
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
			if len(str) != job.Flags.Length {
				// if not the same length, iterate through all possible characters
				// and add them to the queue
				for i := '0'; i < 'z'; i++ {
					queue = append(queue, str+string(i))
				}

			}
			// check the hash
			hasher := sha256.New()
			hasher.Write([]byte(str))
			h := hasher.Sum(nil)

			if reflect.DeepEqual(h, *gs.TargetHash) {
				fmt.Println("Found match:", str)
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

	// check if we ought to be profiling
	if flags.Profile {
		defer profile.Start(
			profile.MemProfile,
		).Stop()
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

	fmt.Println("Target hash:", hex.EncodeToString(h))

	// start 8 workers
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go worker(jobs, &gs)
	}

	for i := '0'; i < 'z'; i++ {
		jobs <- HashJob{i, flags}
	}
	// close the jobs channel
	close(jobs)

	// wait for all workers to finish
	wg.Wait()

	if gs.Done == 0 {
		fmt.Println("No match found, try increasing the length of the string to check")
	}
}
