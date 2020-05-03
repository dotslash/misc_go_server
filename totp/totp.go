package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	// We will compare our implementation with this library's
	"github.com/gokyle/hotp"
	// gozxing.qrcode does not have a nice way to create an qr code from text
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	// skip2/go-qrcode only supports encoding text to qr.
	qrcode2 "github.com/skip2/go-qrcode"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"math"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

var debugMode = flag.Bool("debug", false, "Enable debug mode")
var printTiming = flag.Bool("print_timing", false, "Print timing")

func panicOnErr(err error) {
	if err != nil {
		panic(err)
	}
}

func panicIf(cond bool, msg string) {
	if cond {
		panic(msg)
	}
}

func timeTrack(start time.Time, name string) {
	if *debugMode || *printTiming {
		elapsed := time.Since(start)
		fmt.Printf("%s took %s\n", name, elapsed)
	}
}

func qrToText(qrPath string) string {
	file, err := os.Open(qrPath)
	panicOnErr(err)

	img, _, err := image.Decode(file)
	panicOnErr(err)

	// prepare BinaryBitmap
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	panicOnErr(err)
	// decode image
	qrReader := qrcode.NewQRCodeReader()
	result, err := qrReader.Decode(bmp, nil)
	panicOnErr(err)
	return result.GetText()
}

func randomBytes(nBytes int) []byte {
	randombytes := make([]byte, nBytes)
	_, err := rand.Read(randombytes)
	panicOnErr(err)
	return randombytes
}

type TOTP struct {
	issuer string
	digits int
	secret string
	note   string
}

func (totp *TOTP) secretBytes() []byte {
	// TODO: padding
	secretBytes, err := base32.StdEncoding.DecodeString(totp.secret)
	panicOnErr(err)
	return secretBytes
}

func (totp *TOTP) timeSeqBytes() []byte {
	timeSeq := uint64(time.Now().Unix() / 30)
	if *debugMode {
		fmt.Printf("time Seq: %v\n", timeSeq)
	}
	ret := make([]byte, 8)
	binary.BigEndian.PutUint64(ret, timeSeq)
	return ret
}

func truncateSHA1(inp []byte) int32 {
	if len(inp) != 20 {
		panic(fmt.Sprintf("truncate.inp's length should be 20, but is %v", len(inp)))
	}
	// truncate(MAC) = extract31(MAC, MAC[(19 × 8) + 4:(19 × 8) + 7] × 8)
	// extract31(MAC, i) = MAC[i + 1:i + (4 × 8) − 1]
	// offset is the 4 least signgicant bits of inp => [0,15]
	offset := int32(inp[19] & 0xF)
	// p = inp[offset:offset+4] : offset <= 15. So offset+4 <= 19
	p := binary.BigEndian.Uint32(inp[offset : offset+4])
	// Remove the most significant bit. Now p can be represented as an int32
	// and will not be negative
	p = p & 0x7FFFFFFF
	return int32(p)
}

func (totp *TOTP) OTP() int32 {
	defer timeTrack(time.Now(), "OTP")
	hasher := hmac.New(sha1.New, totp.secretBytes())
	hasher.Write(totp.timeSeqBytes())
	hash := hasher.Sum(nil)
	return truncateSHA1(hash) % int32(math.Pow10(totp.digits))
}

func (totp *TOTP) GokyleOTP() string {
	defer timeTrack(time.Now(), "GokyleOTP")
	secs := time.Now().Unix()
	otp := hotp.NewHOTP(totp.secretBytes(), uint64(secs/30), totp.digits)
	return otp.OTP()
}

func (totp *TOTP) URL() string {
	// otpauth://totp/user_id?issuer=service_name&digits=6&secret=TTTTTOPSECRETTTT
	return fmt.Sprintf(
		"otpauth://totp/%v?issuer=%v&digits=%v&secret=%v",
		totp.note, totp.issuer, totp.digits, totp.secret)
}

func (totp *TOTP) toQR(qrPath string) {
	panicOnErr(qrcode2.WriteFile(totp.URL(), qrcode2.Medium, 256, qrPath))
}

func TOTPFromURL(urlstring string) TOTP {
	u, err := url.Parse(urlstring)
	panicOnErr(err)
	panicIf(u.Scheme != "otpauth" && u.Host != "totp",
		fmt.Sprintf("wrong scheme/host: %v", u))

	digits, err := strconv.Atoi(u.Query().Get("digits"))
	panicIf(digits > 8, "digits should be <= 8")
	panicOnErr(err)
	return TOTP{
		issuer: u.Query().Get("issuer"),
		digits: digits,
		secret: u.Query().Get("secret"),
		note:   strings.TrimLeft(u.Path, "/"),
	}
}

func CreateTOTP(issuer string, digits int, note string) TOTP {
	panicIf(digits > 8, "digits should be <= 8")
	return TOTP{
		issuer: issuer,
		digits: digits,
		note:   note,
		// 20 bytes => 160 bits
		// encode(32*5 bits) => secret is of length 32.
		secret: base32.StdEncoding.EncodeToString(randomBytes(20)),
	}
}

func testCreateTOTPTask() {
	randString := base32.StdEncoding.EncodeToString(randomBytes(10))
	qrPath := "/tmp/totp_" + randString + ".png"
	fmt.Printf("Will save the qr to %v\n", qrPath)
	// 1. Create totp.
	totp1 := CreateTOTP("test_totp.com", 6, "user_"+randString)
	// 2. Write it to qr image.
	totp1.toQR(qrPath)
	// 3. Create TOTP from the qr image.
	totp2 := TOTPFromURL(qrToText(qrPath))
	fmt.Printf("totp1: %#v\n", totp1)
	fmt.Printf("totp2: %#v\n", totp2)
	// 4. Compare both.
	fmt.Printf("OTP       : %v %v\n", totp1.OTP(), totp2.OTP())
	fmt.Printf("GokyleOTP : %v %v\n", totp1.GokyleOTP(), totp2.GokyleOTP())
}

func getOTPTask(qrPath, otpUrl string) {
	panicIf(qrPath == "" && otpUrl == "", "Either otp_qr_path or otp_url must be set")
	if qrPath != "" {
		otpUrl = qrToText(qrPath)
	}
	totp := TOTPFromURL(otpUrl)
	if *debugMode {
		fmt.Printf("URL: %v\n", totp.URL())
	}
	fmt.Println(totp.OTP())
}

func emptyOr(inp, defaultVal string) string {
	if inp == "" {
		return defaultVal
	}
	return inp
}

func createTOTPTask(qrPath, issuer, user string, digits int) {
	panicIf(qrPath == "", "qrPath should be set")
	issuer = emptyOr(issuer, "test_totp.com")
	user = emptyOr(user, base32.StdEncoding.EncodeToString(randomBytes(10)))
	totp := CreateTOTP(issuer, digits, user)
	totp.toQR(qrPath)
	fmt.Printf("Stored totp qr at %v\n", qrPath)
	fmt.Printf("Current totp: %v\n", totp.OTP())
}

func main() {
	task := flag.String("task", "test", "Pick one of {test,create,otp}")
	createQrPath := flag.String(
		"create_qr_path", "",
		"Where to store QR image when task is create. This must be set for create task")
	createIssuer := flag.String(
		"create_issuer", "test_totp.com", "Issuer name to create TOTP")
	createUser := flag.String(
		"create_user", "",
		"User name to create TOTP. If empty a random string will be used.")
	createDigits := flag.Int(
		"create_digits", 6,
		"Number of digits for the TOTP. Relevant for create task only")

	otpQrLocation := flag.String(
		"otp_qr_path", "",
		"Path of the QR code for otp task. For otp task either this or otp_url should be passed")
	otpUrl := flag.String(
		"otp_url", "",
		"TOTP URL for otp task. For otp task either this or otp_qr_path should be specified")

	flag.Parse()
	switch *task {
	case "test":
		testCreateTOTPTask()
	case "otp":
		getOTPTask(*otpQrLocation, *otpUrl)
	case "create":
		createTOTPTask(*createQrPath, *createIssuer, *createUser, *createDigits)
	default:
		panic("Unknown task: " + *task)
	}
}
