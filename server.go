package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/dotslash/misc_go_server/pw"
	"github.com/gorilla/mux"
)

type metadata struct {
	OpTime string `json:"op_time,omitempty"`
}

type PwResponse struct {
	PwHash   string   `json:"pw_hash,omitempty"`
	PwnCnt   int64    `json:"pwn_count,omitempty"`
	ErrorStr string   `json:"error,omitempty"`
	Meta     metadata `json:"meta,omitempty"`
}

// Helper function to complete pw/ routes.
func handlePwHash(w http.ResponseWriter, r *http.Request, pwHash string) {
	start := time.Now()
	pwnCnt, err := pw.GetPwnedCount(pwHash)
	end := time.Now()

	resp := PwResponse{
		PwHash: pwHash,
		PwnCnt: pwnCnt,
		Meta:   metadata{OpTime: end.Sub(start).String()}}
	if err != nil {
		// No error handling. Everything is a 500!
		w.WriteHeader(http.StatusInternalServerError)
		resp = PwResponse{
			PwHash:   pwHash,
			ErrorStr: err.Error(),
			Meta:     metadata{OpTime: end.Sub(start).String()}}
	}
	json.NewEncoder(w).Encode(resp)
}

// Reads body and returns it as a string. Returns error if reading body fails
// or if body is empty.
func readNonEmptyBody(r *http.Request) (string, error) {
	plainPassBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return "", errors.New(fmt.Sprintf("failed to read request body: %v", err.Error()))
	}
	if len(plainPassBytes) == 0 {
		return "", errors.New("body should not be empty.")
	}
	return string(plainPassBytes), nil
}

func setJsonContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

func main() {
	// Flags
	only_secure_pw_plain := flag.Bool(
		"only_secure_pw_plain", true,
		"Servers use_haveibeenpwned_com_instead only on https")
	flag.Parse()

	// Init pw module.
	pw.Init()

	// Routers.
	r := mux.NewRouter()
	r.Use(setJsonContentType) // All responses are json.
	r.HandleFunc("/pw/hashed/{pw_hash}", func(w http.ResponseWriter, r *http.Request) {
		pwHash := mux.Vars(r)["pw_hash"]
		handlePwHash(w, r, pwHash)
	})
	// pw_plain/use_haveibeenpwned_com_instead and hashed/{pw_hash} uses the same
	// backend.
	pw_plain_route := r.HandleFunc(
		"/pw/pw_plain/use_haveibeenpwned_com_instead",
		func(w http.ResponseWriter, r *http.Request) {
			plainPass, err := readNonEmptyBody(r)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(PwResponse{ErrorStr: err.Error()})
				return
			} else {
				pwHash := pw.GetPwHash(plainPass)
				handlePwHash(w, r, pwHash)
			}
		})
	// Serve pw_plain_route only on https.
	if *only_secure_pw_plain {
		pw_plain_route.Schemes("https")
	}
	http.ListenAndServe(":8786", r)
}
