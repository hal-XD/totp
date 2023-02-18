package main

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash"
	"log"
	"math"
)

var Logger *log.Logger

func setLogger(l *log.Logger) {
	Logger = l
}

func logf(format string, v ...interface{}) {
	if Logger != nil {
		Logger.Printf(format, v...)
	}
}

// T0 : 時間の区切りを数え始めるUnixTime
// X  : 時間の区切り
// t = floor((cuurent_unixtime - T0)/X)
// hotpの仕様よりtは8byteで表す。
// eg
//
//	t := make([]byte, 8)
//	binary.BigEndian.PutUint64(t, uint64((ut-0)/30))
func GenerateTotp(algo func() hash.Hash, k string, t []byte) string {
	return hotp(algo, k, t)
}

// HOTPの生成
// c 8byteのcunter value
// k secret
// T throtting parameter
// s
// Digt number 桁数
// HPTP(k,c) = truncate(hmac-sha-1(k,c))
// HOTPはbigendianとして扱われる
func hotp(algo func() hash.Hash, k string, c []byte) string {
	return fmt.Sprint((truncate(hmacWithAlgo(algo, k, c))))
}

// DT(string) // string = string[0]..string[19] (sha1)
// offsetbits := low-order 4 bits of string[19]
// osset = strToNum(offsetbits) // 0 <= offset <= 15
// p = string[offset]..string[offset+3] ... 32bit
// return tha last 31 bits of p
func truncate(hs []byte) uint32 {

	offsetBits := hs[len(hs)-1] & 0x0f
	logf("hs[last]=[%v] offsetBits=[%v]\n", hs[len(hs)-1], offsetBits)

	offset := int(offsetBits)
	logf("offset=[%v] hs[offset]=[%v] hs[offset+1]=[%v] hs[offset+2]=[%v] hs[offset+3]=[%v] hs slice=[%v]\n", offset, hs[offset], hs[offset+1], hs[offset+2], hs[offset+3], hs[offset:offset+4])

	p := binary.BigEndian.Uint32(hs[offset : offset+4])

	logf("p value is [%v]\n", p)
	snum := p & 0x7fffffff
	logf("snum (p value masked 0x7fffffff) is [%v]\n", snum)

	d := snum % uint32(math.Pow10(6))
	logf("digit = [%v]\n", d)

	return d
}

func hmacWithAlgo(algo func() hash.Hash, k string, c []byte) []byte {
	mac := hmac.New(algo, []byte(k))
	mac.Write(c)
	expectedMac := mac.Sum(nil)

	// 20 byteのstringが生成されたことを確認する(sha1の場合)
	logf("expectedMac = [%v] length = [%v]\n", expectedMac, len(expectedMac))
	return expectedMac
}

// otpauthのURIフォーマット
// otpauth://[TYPE]/[LABEL]?[PARAMETERS]
// otpauth://totp/[issuer]:[accountname]?secret=[secret]&issuer=[issuer]&algorithm=SHA1&digits=6&period=30
//
// TYPE : hotp or totp
// LABEL : [issuer]:[accountname]
//
//	issuer/accountnameはURLエンコードする
//
// パラメータ
// secret 秘密鍵をbase32エンコードした文字列
// issuer　発行者(IIJ smartkeyでは必須らしい)
// algorithm : SHA1 or SHA256 or SHA512 (google authenticatorでは無視されるらしい)
// digits : 6 or 8 (google(略))
// period: (g())
type TotpConfig struct {
	Secret      string
	Issuer      string
	AccountName string
	Algorithm   string
	Digits      int
	Period      int
}

// otppathを生成する
func GenerateTotpURI(c TotpConfig) string {
	return fmt.Sprintf("otpauth://totp/%v:%v?secret=%v&issuer=%v?algorithm=%v&digits=%v&period=%v",
		c.Issuer, c.AccountName, c.Secret, c.Issuer, c.Algorithm, c.Digits, c.Period)

}
