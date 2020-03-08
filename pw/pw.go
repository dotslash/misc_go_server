package pw

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/md4"

	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"

	"cloud.google.com/go/bigquery"
	"google.golang.org/api/iterator"
)

var proj string = ""

const pwHashQuery = `
	SELECT * 
	FROM ` + "`booming-client-211100.hibp.pw_hashes`" + `
	WHERE pw_hash = @pw_hash AND ` + "`partition`" + ` = @partition
	LIMIT 1`

// Struct representing schema of pw_hashes table.
type pwHashRow struct {
	// Partition = hex.DecodeString(Hash[:2])
	Partition int64 `bigquery:"partition"`
	// Hash = md4(utf16le.encode(plainPw)).Upper()
	Hash string `bigquery:"pw_hash"`
	// Number of times the password is pwned.
	Count int64 `bigquery:"count"`
}

// Init initializes the module.
func Init() {
	proj = os.Getenv("GOOGLE_CLOUD_PROJECT")
	if proj == "" {
		fmt.Println("GOOGLE_CLOUD_PROJECT environment variable must be set.")
		os.Exit(1)
	}
}

// GetPwHash converts plain text password to `md4(utf16le.encode(plain))`.
func GetPwHash(plainPw string) string {
	enc := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	hasher := md4.New()
	// Set up transformer so that transformer.Write will write
	// bytes to the hasher in utf-16le encoding.
	transformer := transform.NewWriter(hasher, enc)
	transformer.Write([]byte(plainPw))
	// Do the the hash.
	bytes := hasher.Sum(nil)
	// Convert bytes to upper case hex and return.
	return strings.ToUpper(hex.EncodeToString(bytes))
}

// GetPwnedCount returns the number of times the given password hash has been
// pwned. If the password is not pwned, returns 0.
func GetPwnedCount(pwHash string) (int64, error) {
	// 2A... => [42, ....]
	// 42 is the partitionID.
	if len(pwHash) != len("8A79FF89C7DBD4655D22C2CE58970514") {
		return -1, errors.New("input hash is invalid")
	}
	decodedBytes, err := hex.DecodeString(pwHash)
	if err != nil {
		return -1, err
	}
	partitionID := int32(decodedBytes[0])
	rows, err := query(
		pwHashQuery,
		[]bigquery.QueryParameter{
			{Name: "pw_hash", Value: pwHash},
			{Name: "partition", Value: partitionID},
		})
	if err != nil {
		return -1, err
	} else if len(rows) == 0 {
		// No data => pw is not found.
		return 0, nil
	} else {
		// There will be exactly one row.
		return rows[0].Count, nil
	}
}

// Runs the given query password hash query
func query(q string, params []bigquery.QueryParameter) ([]pwHashRow, error) {
	var ctx context.Context = context.Background()
	client, err := bigquery.NewClient(ctx, proj)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	query := client.Query(q)
	query.Parameters = params
	iter, err := query.Read(ctx)
	if err != nil {
		return nil, err
	}
	var rows []pwHashRow
	for {
		var row pwHashRow
		err := iter.Next(&row)
		if err == iterator.Done {
			break
		} else if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
}
