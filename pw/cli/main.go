package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"syscall"
	"strings"
	"time"

	"github.com/dotslash/miscgo/pw"
    "golang.org/x/crypto/ssh/terminal"
)

var debugMode = flag.Bool("debug", false, "Enable debug mode")
var server = flag.String("serverAddress", "", "If empty, gets data from google bigquery. You can use bm.suram.in")

func panicOnErr(err error) {
	if err != nil {
		panic(err)
	}
}

func printTimeElapsed(start time.Time) {
	end := time.Now()
	fmt.Printf("Operation took %v\n", end.Sub(start))
}

func readPassword() string {
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
    panicOnErr(err)
    return string(bytePassword)
}

type metadata struct {
	OpTime string `json:"op_time,omitempty"`
}


type PwResponse struct {
	PwHash   string   `json:"pw_hash,omitempty"`
	PwnCnt   int64    `json:"pwn_count,omitempty"`
	ErrorStr string   `json:"error,omitempty"`
	Meta     metadata `json:"meta,omitempty"`
}

func makeHttpCall(url string) *http.Response {
	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	panicOnErr(err)

	resp, err := client.Do(req)
	panicOnErr(err)
	
	if (*debugMode) {
		dump, err := httputil.DumpRequest(req, true)
		panicOnErr(err)
		fmt.Println("====================================")
		fmt.Println(">>>>>Request<<<<")
		fmt.Println(strings.TrimSpace(string(dump)))
		fmt.Println("<<<<Request>>>>>")


		dump, err = httputil.DumpResponse(resp, true)
		panicOnErr(err)
		fmt.Println(">>>>>Response<<<<")
		fmt.Println(strings.TrimSpace(string(dump)))
		fmt.Println("<<<<Response>>>>>")
		fmt.Println("====================================")

	}
	return resp
}

func getPwnedCount(hashedPw string) (int64, error) {
	if (*server == "") {
		// Use google bigquery.
		return pw.GetPwnedCount(hashedPw)
	}
	normServer := strings.TrimRight(*server, "/") 
	resp := makeHttpCall(fmt.Sprintf("https://%v/pw/hashed/%v", normServer, hashedPw))
	body, err := ioutil.ReadAll(resp.Body)
	panicOnErr(err)
	
	pwresp := PwResponse{}
	json.Unmarshal(body, &pwresp)
	return pwresp.PwnCnt, nil
}

func main() {
	flag.Parse()
	if (*server == "") {
		fmt.Println("Using bigquery as backend")
		pw.InitGCP()
	} else {
		fmt.Printf("Using %v for backend.\n", *server)
	}

	fmt.Printf("Enter password: ")
    plainPw := readPassword()
	fmt.Println()
	if (*debugMode) {
		fmt.Printf("Entered password: %v\n", plainPw)
	}
	defer printTimeElapsed(time.Now())
	hashedPw := pw.GetPwHash(plainPw)
	fmt.Printf("Password hash is %v\n", hashedPw)
	count, err := getPwnedCount(hashedPw)
	panicOnErr(err)
	fmt.Printf("Password is pwned %v times.\n", count)
}
