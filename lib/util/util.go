package util

import (
	"bufio"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func Md5(t []byte) string {
	h := md5.New()
	h.Write(t)
	cipherStr := h.Sum(nil)
	return hex.EncodeToString(cipherStr)
}

func B64Encode(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}

func B64Decode(src string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(src)
}

func RandNum(min, max int) int {
	if min == max {
		return min
	}
	if min > max {
		min, max = max, min
	}
	randNum := rand.Intn(max - min + 1)
	randNum += min
	return randNum
}

func RandStr(n int, letters string) string {
	if letters == "" {
		letters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func Min(num ...int) int {
	min := num[0]
	for _, n := range num {
		if min > n {
			min = n
		}
	}
	return min
}

func Max(num ...int) int {
	max := num[0]
	for _, n := range num {
		if max < n {
			max = n
		}
	}
	return max
}

func ReadFile(file string) (string, error) {
	buf, err := ioutil.ReadFile(file)
	return string(buf), err
}

func ReadLines(file string) ([]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, strings.TrimRight(scanner.Text(), "\r\n"))
	}
	f.Close()
	return lines, scanner.Err()
}

func Write2File(file, text string) (int, error) {
	f, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return f.WriteString(text)
}

func Append2File(file, text string) (int, error) {
	f, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return f.WriteString(text)
}

func WriteLines(file string, lines []string) (int, error) {
	f, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var i int
	var line string
	for i, line = range lines {
		_, err := f.WriteString(line + LF)
		if err != nil {
			return i, err
		}
	}
	return i + 1, nil
}

func LeftPad(str, pad string, length int) string {
	return strings.Repeat(pad, length-len(str)) + str
}

func RightPad(str, pad string, length int) string {
	return str + strings.Repeat(pad, length-len(str))
}

func SubStr(s string, start, length int) string {
	r := []rune(s)
	l := len(r)
	start = start % l
	if start < 0 {
		start = l + start
	}
	length = length % l
	if length < 0 {
		length = l + length
	}
	end := start + length
	if end <= l {
		return string(r[start:end])
	}
	return ""
}

func SplitList(list []string, per int) [][]string {
	var (
		rlines [][]string
		count  = len(list) / per
	)
	if len(list)%per != 0 {
		count += 1
	}
	for i := 0; i < count; i++ {
		start := i * per
		end := (i + 1) * per
		if end > len(list) {
			end = len(list)
		}
		rlines = append(rlines, list[start:end])
	}
	return rlines
}

func GBK2UTF8(in []byte) []byte {
	if !utf8.Valid(in) {
		out, err := simplifiedchinese.GB18030.NewDecoder().Bytes(in)
		if err == nil {
			return out
		}
	}
	return in
}

func CheckIdCard(IdCard string) bool {
	var idCardArr = []byte(strings.ToUpper(strings.TrimSpace(IdCard)))
	if len(idCardArr) < 18 {
		return false
	}
	var weight = [...]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	var validate = [...]byte{49, 48, 88, 57, 56, 55, 54, 53, 52, 51, 50}
	var sum int
	for i := 0; i < len(idCardArr)-1; i++ {
		b, err := strconv.Atoi(string(idCardArr[i]))
		if err != nil {
			return false
		}
		sum += b * weight[i]
	}
	return validate[sum%11] == idCardArr[17]
}

func TimeCost(now time.Time) {
	pc, _, _, _ := runtime.Caller(1)
	log.Printf("%s took %s", runtime.FuncForPC(pc).Name(), time.Since(now))
}

func SelfPid() int {
	return syscall.Getpid()
}

func SelfName() string {
	file, _ := exec.LookPath(os.Args[0])
	absFile, _ := filepath.Abs(file)
	_, name := path.Split(strings.Replace(absFile, `\`, "/", -1))
	return name
}

func Encrypt(src string, key string) string {
	r := ""
	var x int
	var srcR = []rune(src)
	for i := 0; i < len(srcR); i++ {
		x = int(srcR[i])
		for j := 0; j < len(key); j++ {
			x ^= int(key[j])
		}
		r += string(rune(x))
	}
	return r
}

func Decrypt(src string, key string) string {
	return Encrypt(src, key)
}

func IsPublicIP(IP net.IP) bool {
	if IP.IsLoopback() || IP.IsLinkLocalMulticast() || IP.IsLinkLocalUnicast() {
		return false
	}
	if ip4 := IP.To4(); ip4 != nil {
		switch true {
		case ip4[0] == 10:
			return false
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return false
		case ip4[0] == 192 && ip4[1] == 168:
			return false
		case ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127:
			return false
		case ip4[0] == 169 && ip4[1] == 254:
			return false
		default:
			return true
		}
	}
	return false
}
