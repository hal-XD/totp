package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"image/png"
	"os"
	"time"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
)

const (
	// secret for hamc-sha512 - 64bytes
	secret = "3132333435363738393031323334353637383930" +
		"3132333435363738393031323334353637383930" +
		"3132333435363738393031323334353637383930" + "31323334"
	secret1 = "12345678901234567890"
)

func main() {
	ex1()

	// secretをBase34でエンコード
	d := []byte("12345678901234567890")
	dst := make([]byte, base32.StdEncoding.EncodedLen(len(d)))
	base32.StdEncoding.Encode(dst, d)
	fmt.Println(string(dst))

	// 認証用鍵受け渡し用QRコード生成
	c := TotpConfig{
		Issuer:      "TOTPexample",
		AccountName: "user1matumotokiyoshi",
		Secret:      string(dst),
		Algorithm:   "SHA512",
		Digits:      6,
		Period:      30,
	}
	u := GenerateTotpURI(c)
	fmt.Println(u)
	qrpng(u)
}

func ex1() {

	//k := "3132333435363738393031323334353637383930"
	k := "12345678901234567890"
	ut := time.Now().Unix()
	//ut := 59
	//ut := 1111111109
	t := make([]byte, 8)
	binary.BigEndian.PutUint64(t, uint64((ut-0)/30))
	fmt.Printf("unixtime=[%v]\nT=[%v]\n", ut, t)
	c1 := GenerateTotp(sha1.New, k, []byte(t))
	c2 := GenerateTotp(sha256.New, k, []byte(t))
	c3 := GenerateTotp(sha512.New, k, []byte(t))
	fmt.Println(c1, c2, c3)
}

func qrpng(uri string) {
	// Create the barcode
	qrCode, _ := qr.Encode(uri, qr.M, qr.Auto)

	// Scale the barcode to 200x200 pixels
	qrCode, _ = barcode.Scale(qrCode, 200, 200)

	// create the output file
	file, _ := os.Create("totp_secret.png")
	defer file.Close()

	// encode the barcode as png
	png.Encode(file, qrCode)
}
