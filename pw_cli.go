package main

import (
	"fmt"
	"log"
	"time"

	"github.com/dotslash/misc_go_server/pw"
)

func printTimeElapsed(start time.Time) {
	end := time.Now()
	fmt.Printf("Operation took %v\n", end.Sub(start))
}

func main() {
	pw.Init()

	var plainPw string
	fmt.Scanln(&plainPw)
	defer printTimeElapsed(time.Now())
	hashedPw := pw.GetPwHash(plainPw)
	fmt.Printf("Password hash is %v\n", hashedPw)
	count, err := pw.GetPwnedCount(hashedPw)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("Password is pwned %v times.\n", count)
}
