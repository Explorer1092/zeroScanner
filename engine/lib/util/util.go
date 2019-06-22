package util

import (
	"bufio"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"html"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func Substr(s string, start, length int) string {
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

func CheckKeyword(keywords []string, body string) (string, bool) {
	for _, keyword := range keywords {
		if strings.Index(body, keyword) >= 0 {
			return keyword, true
		}
	}
	return "", false
}

// 从字符串中查找数组中出现的关键字
func IsKeywordExist(keywords []string, body string) bool {
	for _, keyword := range keywords {
		if strings.Index(body, keyword) >= 0 {
			return true
		}
	}
	return false
}

// 检查关键字是否在数组中，若不在，则插入首位
func CheckAndInsert(list []string, key string) []string {
	if !ContainsStr(list, key) {
		return InsertStr(list, key, 0)
	}
	return list
}

// 检查路径是否在数组中，若不在，则插入首位
func CheckAndInsertPath(paths []string, path string) []string {
	cp := path
	if cp == "" {
		cp = "/"
	}
	if !ContainsStr(paths, cp) {
		return InsertStr(paths, path, 0)
	}
	return paths
}

// path不为"/"或""则返回path，否则返回paths，用在需要扫描url的path，并且有自定义path的poc中，防止对同一个域名出现不同的path时重复扫描自定义的path
func GetPaths(paths []string, path string) []string {
	if path != "" && path != "/" {
		return []string{path}
	}
	return paths
}

// port不为""则返回port，否则返回ports，用在需要同时检测url和host的poc中，防止对同一个域名重复扫描poc中定义的端口
func GetPorts(ports []string, port string, path string) []string {
	if path != "" && path != "/" {
		return []string{port}
	}
	return ports
}

func ContainsStr(list []string, item string) bool {
	for _, v := range list {
		if v == item {
			return true
		}
	}
	return false
}

func ContainsInt(list []int, item int) bool {
	for _, v := range list {
		if v == item {
			return true
		}
	}
	return false
}

func InsertStr(slice []string, item string, i int) []string {
	s := append(slice, "")
	copy(s[i+1:], slice[i:])
	s[i] = item
	return s
}

func InsertInt(slice []int, item, i int) []int {
	s := append(slice, 0)
	copy(s[i+1:], slice[i:])
	s[i] = item
	return s
}

func Md5(src []byte) string {
	h := md5.New()
	h.Write(src)
	cipherStr := h.Sum(nil)
	return hex.EncodeToString(cipherStr)
}

func B64Encode(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}

func B64Decode(src string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(src)
}

func HtmlEncode(src string) string {
	return html.EscapeString(src)

}

func HtmlDecode(src string) string {
	return html.UnescapeString(src)
}

//slice去重
func RemoveDupStr(slice []string) []string {
	var (
		keyExists = struct{}{}
		s         = make(map[string]struct{})
		newSlice  = []string{}
	)
	for _, v := range slice {
		if _, has := s[v]; !has {
			newSlice = append(newSlice, v)
			s[v] = keyExists
		}
	}
	return newSlice
}

//slice去重
func RemoveDupInt(slice []int) []int {
	var (
		keyExists = struct{}{}
		s         = make(map[int]struct{})
		newSlice  = []int{}
	)
	for _, v := range slice {
		if _, has := s[v]; !has {
			newSlice = append(newSlice, v)
			s[v] = keyExists
		}
	}
	return newSlice
}

//解码到utf-8格式（支持gb18030及其子集，包含gbk，gb2312）
func GBK2UTF8(src []byte) []byte {
	if !utf8.Valid(src) {
		out, err := simplifiedchinese.GB18030.NewDecoder().Bytes(src)
		if err == nil {
			return out
		}
	}
	return src
}

func ReadLines(fileName string) ([]string, error) {
	f, err := os.Open(filepath.Join("./source/", filepath.Clean(fileName)))
	if err != nil {
		return nil, err
	}
	lines := []string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, strings.TrimRight(scanner.Text(), "\r\n"))
	}
	f.Close()
	return lines, scanner.Err()
}

func ReadFile(fileName string) ([]byte, error) {
	return ioutil.ReadFile(filepath.Join("./source/", filepath.Clean(fileName)))
}

//生成指定范围内随机数字
func RandInt(min, max int) int {
	if min > max {
		min, max = max, min
	}
	if min == max {
		return min
	}
	randNum := rand.Intn(max - min + 1)
	randNum = randNum + min
	return randNum
}

//生成随机字符串，第二个参数可选，为字符集
func RandString(n int, letters string) string {
	if letters == "" {
		letters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func CheckIdCard(idCard string) bool {
	var idCardArr = []byte(strings.ToUpper(strings.TrimSpace(idCard)))
	if len(idCardArr) < 18 {
		return false
	}

	var (
		weight   = [...]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
		validate = [...]byte{49, 48, 88, 57, 56, 55, 54, 53, 52, 51, 50}
		sum      int
	)

	for i := 0; i < len(idCardArr)-1; i++ {
		b, err := strconv.Atoi(string(idCardArr[i]))
		if err != nil {
			return false
		}
		sum += b * weight[i]
	}
	return validate[sum%11] == idCardArr[17]
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

//相似度，基于最小编辑距离算法
func Similar(str1, str2 string) int {
	count, max := levenshtein(str1, str2)
	return (max - count) * 100 / max
}

//最小编辑距离算法
func levenshtein(str1, str2 string) (int, int) {
	var cost, lastdiag, olddiag, p int

	s1 := []rune(str1)
	s2 := []rune(str2)

	len1 := len(s1)
	len2 := len(s2)

	max := len1
	if max < len2 {
		max = len2
	}

	for ; p < len1 && p < len2; p++ {
		if s2[p] != s1[p] {
			break
		}
	}
	s1, s2 = s1[p:], s2[p:]
	len1 -= p
	len2 -= p

	for 0 < len1 && 0 < len2 {
		if s1[len1-1] != s2[len2-1] {
			s1, s2 = s1[:len1], s2[:len2]
			break
		}
		len1--
		len2--
	}

	if len1 == 0 {
		return len2, max
	}

	if len2 == 0 {
		return len1, max
	}

	column := make([]int, len1+1)

	for y := 1; y <= len1; y++ {
		column[y] = y
	}

	for x := 1; x <= len2; x++ {
		column[0] = x
		lastdiag = x - 1
		for y := 1; y <= len1; y++ {
			olddiag = column[y]
			cost = 0
			if s1[y-1] != s2[x-1] {
				cost = 1
			}
			column[y] = Min(
				column[y]+1,
				column[y-1]+1,
				lastdiag+cost)
			lastdiag = olddiag
		}
	}
	return column[len1], max
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

func IsPublic(address string) bool {
	ips, err := net.LookupIP(address)
	if err != nil || len(ips) == 0 {
		return false
	}
	var IP net.IP
	for _, IP = range ips {
		if IP.To4() != nil {
			break
		}
	}
	if IP.IsLoopback() || IP.IsLinkLocalMulticast() || IP.IsLinkLocalUnicast() {
		return false
	}
	if ip4 := IP.To4(); ip4 != nil {
		switch true {
		case ip4[0] == 10:
			return false
		// 11,19,20,21,22开头的ip为公司公网私用ip段
		case ip4[0] == 11:
			return false
		case ip4[0] == 19:
			return false
		case ip4[0] == 20:
			return false
		case ip4[0] == 21:
			return false
		case ip4[0] == 22:
			return false
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return false
		case ip4[0] == 192 && ip4[1] == 168:
			return false
		case ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127:
			return false
		default:
			return true
		}
	}
	return false
}
