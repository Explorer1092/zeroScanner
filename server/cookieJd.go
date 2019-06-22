package main

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/robertkrimen/otto"
)

type CookieJd struct {
	pin           string
	password      string
	erpUser       string
	erpPass       string
	cookies       map[string]string
	refreshMinute int
	ckUpdateTime  time.Time
	sidUpdateTime time.Time
}

func (self *CookieJd) doHttpGetRequest(client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	return client.Do(req)
}

func (self *CookieJd) newClient() *http.Client {
	client := new(http.Client)
	client.Jar, _ = cookiejar.New(nil)
	client.Timeout = time.Second * 5
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// 测试
	//	transport := new(http.Transport)
	//	parsedProxyUrl, _ := url.Parse("http://127.0.0.1:8080")
	//	transport.Proxy = http.ProxyURL(parsedProxyUrl)
	//	client.Transport = transport
	// 测试

	return client
}

func (self *CookieJd) getMbSid(client *http.Client) (string, error) {
	resp, err := self.doHttpGetRequest(client, "https://m.jd.com/")
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	for _, ck := range resp.Cookies() {
		if ck.Name == "sid" {
			return ck.Value, nil
		}
	}
	return "", nil
}

func (self *CookieJd) md5(str string) string {
	md5Ins := md5.New()
	md5Ins.Write([]byte(str))
	return hex.EncodeToString(md5Ins.Sum(nil))
}

func (self *CookieJd) getMbDat(body string) (string, error) {
	//原函数并没有用到username,pwd，为了保持一致还是带过来了。
	ptnGetDat := regexp.MustCompile(`(?m)function\s+getDat\(username,pwd\)\s+\{return\s+md5\(([\s\S]*?)\);\}`)
	ptnEachExp := regexp.MustCompile(`\w+\('[^']+'\)|'[^']+'(\.[^+;]*)?`)
	ptnQuoteValue := regexp.MustCompile(`'([^']*?)'`)
	ptnCharAtValue := regexp.MustCompile(`\((\d+)\)`)

	getDatStringMatch := ptnGetDat.FindStringSubmatch(body)
	if getDatStringMatch == nil {
		return "", errors.New("can not find getDat function")
	}

	var result, para string
	for _, v := range ptnEachExp.FindAllString(getDatStringMatch[1], -1) {
		switch {
		case strings.Contains(v, "md5("):
			para = ptnQuoteValue.FindStringSubmatch(v)[1]
			result = result + self.md5(para)
		case strings.Contains(v, "charAt("):
			para = ptnQuoteValue.FindStringSubmatch(v)[1]
			index, err := strconv.Atoi(ptnCharAtValue.FindStringSubmatch(v)[1])
			if err != nil {
				return "", err
			}
			result = result + string(para[index])
		case strings.Contains(v, "toLowerCase("):
			para = ptnQuoteValue.FindStringSubmatch(v)[1]
			result = result + strings.ToLower(para)
		case strings.Contains(v, "toUpperCase("):
			para = ptnQuoteValue.FindStringSubmatch(v)[1]
			result = result + strings.ToUpper(para)
		case strings.Contains(v, "substr("):
			para = ptnQuoteValue.FindStringSubmatch(v)[1]
			index, err := strconv.Atoi(ptnCharAtValue.FindStringSubmatch(v)[1])
			if err != nil {
				return "", err
			}
			result = result + para[index:]
		default:
			para = ptnQuoteValue.FindStringSubmatch(v)[1]
			result = result + para
		}
	}
	return self.md5(result), nil
}

func (self *CookieJd) getMbRsaString(body string) (string, error) {

	ptnRsaString := regexp.MustCompile(`str_rsaString\s*=\s["']([0-9a-fA-F]{256})`)

	rsaStringMatch := ptnRsaString.FindStringSubmatch(body)
	if rsaStringMatch == nil {
		return "", errors.New("can not find rsaString")
	}
	return rsaStringMatch[1], nil
}

func (self *CookieJd) getMbSToken(body string) (string, error) {

	ptnSToken := regexp.MustCompile(`str_kenString\s*=\s["'](\w+)['"]`)

	sTokenMatch := ptnSToken.FindStringSubmatch(body)
	if sTokenMatch == nil {
		return "", errors.New("can not find str_kenString")
	}

	return sTokenMatch[1], nil
}

//func GetRiskJdToken(client *http.Client) (string, error) {
//	resp, err := doHttpGetRequest(client, "https://payrisk.jd.com/m.html")
//	defer resp.Body.Close()
//	if err != nil {
//		return "", err
//	}
//	body, err := ioutil.ReadAll(resp.Body)
//	if err != nil {
//		return "", err
//	}
//	ptnRiskJdToken, err := regexp.Compile(`jd_risk_token_id\s*=\s["'](\w+)['"]`)
//	if err != nil {
//		return "", err
//	}
//	var riskJdToken string
//	if ptnRiskJdToken.MatchString(string(body)) {
//		riskJdToken = string(ptnRiskJdToken.FindStringSubmatch(string(body))[1])
//	} else {
//		return "", errors.New("can not find jd_risk_token_id")
//	}
//	return riskJdToken, nil
//}

func (self *CookieJd) getMbEncryptedInfo(rsaString string) (string, string, error) {
	vm := otto.New()
	vm.Set("rsaString", rsaString)
	vm.Set("pwd", self.password)
	vm.Set("username", self.pin)
	vm.Run(`
	function BarrettMu(i){this.modulus=biCopy(i),this.k=biHighIndex(this.modulus)+1;var t=new BigInt;t.digits[2*this.k]=1,this.mu=biDivide(t,this.modulus),this.bkplus1=new BigInt,this.bkplus1.digits[this.k+1]=1,this.modulo=BarrettMu_modulo,this.multiplyMod=BarrettMu_multiplyMod,this.powMod=BarrettMu_powMod}function BarrettMu_modulo(i){var t=biDivideByRadixPower(i,this.k-1),r=biMultiply(t,this.mu),e=biDivideByRadixPower(r,this.k+1),n=biModuloByRadixPower(i,this.k+1),g=biMultiply(e,this.modulus),s=biModuloByRadixPower(g,this.k+1),d=biSubtract(n,s);d.isNeg&&(d=biAdd(d,this.bkplus1));for(var o=biCompare(d,this.modulus)>=0;o;)d=biSubtract(d,this.modulus),o=biCompare(d,this.modulus)>=0;return d}function BarrettMu_multiplyMod(i,t){var r=biMultiply(i,t);return this.modulo(r)}function BarrettMu_powMod(i,t){var r=new BigInt;r.digits[0]=1;for(var e=i,n=t;;){if(0!=(1&n.digits[0])&&(r=this.multiplyMod(r,e)),n=biShiftRight(n,1),0==n.digits[0]&&0==biHighIndex(n))break;e=this.multiplyMod(e,e)}return r}function setMaxDigits(i){maxDigits=i,ZERO_ARRAY=new Array(maxDigits);for(var t=0;t<ZERO_ARRAY.length;t++)ZERO_ARRAY[t]=0;bigZero=new BigInt,bigOne=new BigInt,bigOne.digits[0]=1}function BigInt(i){"boolean"==typeof i&&1==i?this.digits=null:this.digits=ZERO_ARRAY.slice(0),this.isNeg=!1}function biFromDecimal(i){for(var t,r="-"==i.charAt(0),e=r?1:0;e<i.length&&"0"==i.charAt(e);)++e;if(e==i.length)t=new BigInt;else{var n=i.length-e,g=n%dpl10;for(0==g&&(g=dpl10),t=biFromNumber(Number(i.substr(e,g))),e+=g;e<i.length;)t=biAdd(biMultiply(t,lr10),biFromNumber(Number(i.substr(e,dpl10)))),e+=dpl10;t.isNeg=r}return t}function biCopy(i){var t=new BigInt((!0));return t.digits=i.digits.slice(0),t.isNeg=i.isNeg,t}function biFromNumber(i){var t=new BigInt;t.isNeg=i<0,i=Math.abs(i);for(var r=0;i>0;)t.digits[r++]=i&maxDigitVal,i>>=biRadixBits;return t}function reverseStr(i){for(var t="",r=i.length-1;r>-1;--r)t+=i.charAt(r);return t}function biToString(i,t){var r=new BigInt;r.digits[0]=t;for(var e=biDivideModulo(i,r),n=hexatrigesimalToChar[e[1].digits[0]];1==biCompare(e[0],bigZero);)e=biDivideModulo(e[0],r),digit=e[1].digits[0],n+=hexatrigesimalToChar[e[1].digits[0]];return(i.isNeg?"-":"")+reverseStr(n)}function biToDecimal(i){var t=new BigInt;t.digits[0]=10;for(var r=biDivideModulo(i,t),e=String(r[1].digits[0]);1==biCompare(r[0],bigZero);)r=biDivideModulo(r[0],t),e+=String(r[1].digits[0]);return(i.isNeg?"-":"")+reverseStr(e)}function digitToHex(t){var r=15,e="";for(i=0;i<4;++i)e+=hexToChar[t&r],t>>>=4;return reverseStr(e)}function biToHex(i){for(var t="",r=(biHighIndex(i),biHighIndex(i));r>-1;--r)t+=digitToHex(i.digits[r]);return t}function charToHex(i){var t,r=48,e=r+9,n=97,g=n+25,s=65,d=90;return t=i>=r&&i<=e?i-r:i>=s&&i<=d?10+i-s:i>=n&&i<=g?10+i-n:0}function hexToDigit(i){for(var t=0,r=Math.min(i.length,4),e=0;e<r;++e)t<<=4,t|=charToHex(i.charCodeAt(e));return t}function biFromHex(i){for(var t=new BigInt,r=i.length,e=r,n=0;e>0;e-=4,++n)t.digits[n]=hexToDigit(i.substr(Math.max(e-4,0),Math.min(e,4)));return t}function biFromString(i,t){var r="-"==i.charAt(0),e=r?1:0,n=new BigInt,g=new BigInt;g.digits[0]=1;for(var s=i.length-1;s>=e;s--){var d=i.charCodeAt(s),o=charToHex(d),a=biMultiplyDigit(g,o);n=biAdd(n,a),g=biMultiplyDigit(g,t)}return n.isNeg=r,n}function biToBytes(i){for(var t="",r=biHighIndex(i);r>-1;--r)t+=digitToBytes(i.digits[r]);return t}function digitToBytes(i){var t=String.fromCharCode(255&i);i>>>=8;var r=String.fromCharCode(255&i);return r+t}function biDump(i){return(i.isNeg?"-":"")+i.digits.join(" ")}function biAdd(i,t){var r;if(i.isNeg!=t.isNeg)t.isNeg=!t.isNeg,r=biSubtract(i,t),t.isNeg=!t.isNeg;else{r=new BigInt;for(var e,n=0,g=0;g<i.digits.length;++g)e=i.digits[g]+t.digits[g]+n,r.digits[g]=65535&e,n=Number(e>=biRadix);r.isNeg=i.isNeg}return r}function biSubtract(i,t){var r;if(i.isNeg!=t.isNeg)t.isNeg=!t.isNeg,r=biAdd(i,t),t.isNeg=!t.isNeg;else{r=new BigInt;var e,n;n=0;for(var g=0;g<i.digits.length;++g)e=i.digits[g]-t.digits[g]+n,r.digits[g]=65535&e,r.digits[g]<0&&(r.digits[g]+=biRadix),n=0-Number(e<0);if(n==-1){n=0;for(var g=0;g<i.digits.length;++g)e=0-r.digits[g]+n,r.digits[g]=65535&e,r.digits[g]<0&&(r.digits[g]+=biRadix),n=0-Number(e<0);r.isNeg=!i.isNeg}else r.isNeg=i.isNeg}return r}function biHighIndex(i){for(var t=i.digits.length-1;t>0&&0==i.digits[t];)--t;return t}function biNumBits(i){var t,r=biHighIndex(i),e=i.digits[r],n=(r+1)*bitsPerDigit;for(t=n;t>n-bitsPerDigit&&0==(32768&e);--t)e<<=1;return t}function biMultiply(i,t){for(var r,e,n,g=new BigInt,s=biHighIndex(i),d=biHighIndex(t),o=0;o<=d;++o){for(r=0,n=o,j=0;j<=s;++j,++n)e=g.digits[n]+i.digits[j]*t.digits[o]+r,g.digits[n]=e&maxDigitVal,r=e>>>biRadixBits;g.digits[o+s+1]=r}return g.isNeg=i.isNeg!=t.isNeg,g}function biMultiplyDigit(i,t){var r,e,n;result=new BigInt,r=biHighIndex(i),e=0;for(var g=0;g<=r;++g)n=result.digits[g]+i.digits[g]*t+e,result.digits[g]=n&maxDigitVal,e=n>>>biRadixBits;return result.digits[1+r]=e,result}function arrayCopy(i,t,r,e,n){for(var g=Math.min(t+n,i.length),s=t,d=e;s<g;++s,++d)r[d]=i[s]}function biShiftLeft(i,t){var r=Math.floor(t/bitsPerDigit),e=new BigInt;arrayCopy(i.digits,0,e.digits,r,e.digits.length-r);for(var n=t%bitsPerDigit,g=bitsPerDigit-n,s=e.digits.length-1,d=s-1;s>0;--s,--d)e.digits[s]=e.digits[s]<<n&maxDigitVal|(e.digits[d]&highBitMasks[n])>>>g;return e.digits[0]=e.digits[s]<<n&maxDigitVal,e.isNeg=i.isNeg,e}function biShiftRight(i,t){var r=Math.floor(t/bitsPerDigit),e=new BigInt;arrayCopy(i.digits,r,e.digits,0,i.digits.length-r);for(var n=t%bitsPerDigit,g=bitsPerDigit-n,s=0,d=s+1;s<e.digits.length-1;++s,++d)e.digits[s]=e.digits[s]>>>n|(e.digits[d]&lowBitMasks[n])<<g;return e.digits[e.digits.length-1]>>>=n,e.isNeg=i.isNeg,e}function biMultiplyByRadixPower(i,t){var r=new BigInt;return arrayCopy(i.digits,0,r.digits,t,r.digits.length-t),r}function biDivideByRadixPower(i,t){var r=new BigInt;return arrayCopy(i.digits,t,r.digits,0,r.digits.length-t),r}function biModuloByRadixPower(i,t){var r=new BigInt;return arrayCopy(i.digits,0,r.digits,0,t),r}function biCompare(i,t){if(i.isNeg!=t.isNeg)return 1-2*Number(i.isNeg);for(var r=i.digits.length-1;r>=0;--r)if(i.digits[r]!=t.digits[r])return i.isNeg?1-2*Number(i.digits[r]>t.digits[r]):1-2*Number(i.digits[r]<t.digits[r]);return 0}function biDivideModulo(i,t){var r,e,n=biNumBits(i),g=biNumBits(t),s=t.isNeg;if(n<g)return i.isNeg?(r=biCopy(bigOne),r.isNeg=!t.isNeg,i.isNeg=!1,t.isNeg=!1,e=biSubtract(t,i),i.isNeg=!0,t.isNeg=s):(r=new BigInt,e=biCopy(i)),new Array(r,e);r=new BigInt,e=i;for(var d=Math.ceil(g/bitsPerDigit)-1,o=0;t.digits[d]<biHalfRadix;)t=biShiftLeft(t,1),++o,++g,d=Math.ceil(g/bitsPerDigit)-1;e=biShiftLeft(e,o),n+=o;for(var a=Math.ceil(n/bitsPerDigit)-1,u=biMultiplyByRadixPower(t,a-d);biCompare(e,u)!=-1;)++r.digits[a-d],e=biSubtract(e,u);for(var b=a;b>d;--b){var l=b>=e.digits.length?0:e.digits[b],h=b-1>=e.digits.length?0:e.digits[b-1],f=b-2>=e.digits.length?0:e.digits[b-2],c=d>=t.digits.length?0:t.digits[d],m=d-1>=t.digits.length?0:t.digits[d-1];l==c?r.digits[b-d-1]=maxDigitVal:r.digits[b-d-1]=Math.floor((l*biRadix+h)/c);for(var x=r.digits[b-d-1]*(c*biRadix+m),v=l*biRadixSquared+(h*biRadix+f);x>v;)--r.digits[b-d-1],x=r.digits[b-d-1]*(c*biRadix|m),v=l*biRadix*biRadix+(h*biRadix+f);u=biMultiplyByRadixPower(t,b-d-1),e=biSubtract(e,biMultiplyDigit(u,r.digits[b-d-1])),e.isNeg&&(e=biAdd(e,u),--r.digits[b-d-1])}return e=biShiftRight(e,o),r.isNeg=i.isNeg!=s,i.isNeg&&(r=s?biAdd(r,bigOne):biSubtract(r,bigOne),t=biShiftRight(t,o),e=biSubtract(t,e)),0==e.digits[0]&&0==biHighIndex(e)&&(e.isNeg=!1),new Array(r,e)}function biDivide(i,t){return biDivideModulo(i,t)[0]}function biModulo(i,t){return biDivideModulo(i,t)[1]}function biMultiplyMod(i,t,r){return biModulo(biMultiply(i,t),r)}function biPow(i,t){for(var r=bigOne,e=i;;){if(0!=(1&t)&&(r=biMultiply(r,e)),t>>=1,0==t)break;e=biMultiply(e,e)}return r}function biPowMod(i,t,r){for(var e=bigOne,n=i,g=t;;){if(0!=(1&g.digits[0])&&(e=biMultiplyMod(e,n,r)),g=biShiftRight(g,1),0==g.digits[0]&&0==biHighIndex(g))break;n=biMultiplyMod(n,n,r)}return e}function RSAKeyPair(i,t,r,e){this.e=biFromHex(i),this.d=biFromHex(t),this.m=biFromHex(r),"number"!=typeof e?this.chunkSize=2*biHighIndex(this.m):this.chunkSize=e/8,this.radix=16,this.barrett=new BarrettMu(this.m)}function encryptedString(i,t,r,e){var n,g,s,d,o,a,u,b,l,h,f=new Array,c=t.length,m="";for(d="string"==typeof r?r==RSAAPP.NoPadding?1:r==RSAAPP.PKCS1Padding?2:0:0,o="string"==typeof e&&e==RSAAPP.RawEncoding?1:0,1==d?c>i.chunkSize&&(c=i.chunkSize):2==d&&c>i.chunkSize-11&&(c=i.chunkSize-11),n=0,g=2==d?c-1:i.chunkSize-1;n<c;)d?f[g]=t.charCodeAt(n):f[n]=t.charCodeAt(n),n++,g--;for(1==d&&(n=0),g=i.chunkSize-c%i.chunkSize;g>0;){if(2==d){for(a=Math.floor(256*Math.random());!a;)a=Math.floor(256*Math.random());f[n]=a}else f[n]=0;n++,g--}for(2==d&&(f[c]=0,f[i.chunkSize-2]=2,f[i.chunkSize-1]=0),u=f.length,n=0;n<u;n+=i.chunkSize){for(b=new BigInt,g=0,s=n;s<n+i.chunkSize;++g)b.digits[g]=f[s++],b.digits[g]+=f[s++]<<8;l=i.barrett.powMod(b,i.e),h=1==o?biToBytes(l):16==i.radix?biToHex(l):biToString(l,i.radix),m+=h}return m}function decryptedString(i,t){var r,e,n,g,s=t.split(" "),d="";for(e=0;e<s.length;++e)for(g=16==i.radix?biFromHex(s[e]):biFromString(s[e],i.radix),r=i.barrett.powMod(g,i.d),n=0;n<=biHighIndex(r);++n)d+=String.fromCharCode(255&r.digits[n],r.digits[n]>>8);return 0==d.charCodeAt(d.length-1)&&(d=d.substring(0,d.length-1)),d}var biRadixBase=2,biRadixBits=16,bitsPerDigit=biRadixBits,biRadix=65536,biHalfRadix=biRadix>>>1,biRadixSquared=biRadix*biRadix,maxDigitVal=biRadix-1,maxInteger=9999999999999998,maxDigits,ZERO_ARRAY,bigZero,bigOne;setMaxDigits(20);var dpl10=15,lr10=biFromNumber(1e15),hexatrigesimalToChar=new Array("0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z"),hexToChar=new Array("0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"),highBitMasks=new Array(0,32768,49152,57344,61440,63488,64512,65024,65280,65408,65472,65504,65520,65528,65532,65534,65535),lowBitMasks=new Array(0,1,3,7,15,31,63,127,255,511,1023,2047,4095,8191,16383,32767,65535),RSAAPP={};RSAAPP.NoPadding="NoPadding",RSAAPP.PKCS1Padding="PKCS1Padding",RSAAPP.RawEncoding="RawEncoding",RSAAPP.NumericEncoding="NumericEncoding",function(){function i(i){var t=new Image,r="";for(var e in i)r+="&"+e+"="+encodeURIComponent(i[e]);r="https://wlmonitor.m.jd.com/web_login_report?"+r.substring(1),t.src=r}function t(i,r){if("object"==typeof r&&null!=r)for(var e in r)"object"==typeof r[e]?(i[e]=r[e].length?[]:{},t(i[e],r[e])):i[e]=r[e]}function r(i){for(var t=location.search.substring(1),r=t.split("&"),e={},n=0;n<r.length;n++){var g=r[n].split("=");e[g[0]]=g[1]}return e[i]?e[i]:""}function e(i){var t=document.cookie.match(new RegExp("(^| )"+i+"=([^;]*)($|;)"));return t?decodeURIComponent(t[2]):""}var n=function(n){var g=r("appid"),s=e("guid"),d=e("pin"),o={appID:g?parseInt(g,10):100,interfaceID:0,loginName:"",uuid:s,pin:d,guid:s,os:"5",netType:"",appVersion:"1.3.0",status:"",callTime:0};t(o,n),i(o)};}
    setMaxDigits(131);
    keyPair = new RSAKeyPair("3", "10001", rsaString, 1024);
    encrytedPwd = encryptedString(keyPair, pwd, RSAAPP.PKCS1Padding, RSAAPP.RawEncoding);
    encrytedUsername = encryptedString(keyPair, username, RSAAPP.PKCS1Padding, RSAAPP.RawEncoding);
	strifyEcptPwd = ""
	for (i=0;i<encrytedPwd.length;i++){
		strifyEcptPwd= strifyEcptPwd + encrytedPwd.charCodeAt(i)+ ",";
	}
	strifyEcptUsername = ""
	for (i=0;i<encrytedUsername.length;i++){
		strifyEcptUsername= strifyEcptUsername + encrytedUsername.charCodeAt(i)+ ",";
	}
	`)
	var username string
	var pwd string
	if value, err := vm.Get("strifyEcptUsername"); err == nil {
		test, _ := value.ToString()
		x := strings.Split(test, ",")
		end := len(x) - 1
		r := []byte{}
		for k, v := range x {
			if k != end {
				i, _ := strconv.Atoi(v)
				r = append(r, self.int2Byte(i))
			}
		}
		username = base64.StdEncoding.EncodeToString(r)
	} else {
		return "", "", err
	}
	if value, err := vm.Get("strifyEcptPwd"); err == nil {
		test, _ := value.ToString()
		x := strings.Split(test, ",")
		end := len(x) - 1
		r := []byte{}
		for k, v := range x {
			if k != end {
				i, _ := strconv.Atoi(v)
				r = append(r, self.int2Byte(i))
			}
		}
		pwd = base64.StdEncoding.EncodeToString(r)
	} else {
		return "", "", err
	}
	return username, pwd, nil
}
func (self *CookieJd) int2Byte(x int) byte {
	y := int32(x)
	b_buf := bytes.NewBuffer([]byte{})
	binary.Write(b_buf, binary.BigEndian, y)
	z := b_buf.Bytes()[3] //int32转成byte后是一个4个元素的数组,根据需求这里只取最后一个元素
	return z              //所以传过来的int值不能大于一个十六进制所能表达的最大数，也就是0xFF/255，否则不准确啊
}

//激活sid
func (self *CookieJd) activeSid(client *http.Client, sid string) {

	urlStr := "https://home.m.jd.com/myJd/home.action?sid=" + sid
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		server.Logger.Error(err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

func (self *CookieJd) doMbLogin(client *http.Client, encryptedUsername string, encryptedPwd string, sToken string, dat string, wlfstkDatk string, referer string) (*http.Response, error) {

	body := strings.NewReader("username=" + encryptedUsername + "&pwd=" + encryptedPwd + "&remember=true&s_token=" + sToken + "&dat=" + dat + "&wlfstk_datk=" + wlfstkDatk + "")
	urlStr := "https://plogin.m.jd.com/cgi-bin/m/domlogin"
	req, _ := http.NewRequest("POST", urlStr, body)

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Origin", "https://plogin.m.jd.com")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", referer)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")

	return client.Do(req)
}

func (self *CookieJd) getMbCookie() string {
	server.Logger.Info("updateing MB cookie")
	client := self.newClient()
	sid, err := self.getMbSid(client)
	if err != nil {
		server.Logger.Error(err)
		return ""
	}
	loginUrl := "https://plogin.m.jd.com/user/login.action?appid=100&kpkey=&returnurl=http%3A%2F%2Fhome.m.jd.com%2FmyJd%2Fhome.action%3Fsid%3D" + sid
	resp, err := self.doHttpGetRequest(client, loginUrl)
	if err != nil {
		server.Logger.Error(err)
		return ""
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		server.Logger.Error(err)
		return ""
	}
	dat, err := self.getMbDat(string(body))
	if err != nil {
		server.Logger.Error(err)
		return ""
	}
	wlfstkDatk := dat
	rsaString, err := self.getMbRsaString(string(body))
	if err != nil {
		server.Logger.Error(err)
		return ""
	}
	sToken, err := self.getMbSToken(string(body))
	if err != nil {
		server.Logger.Error(err)
		return ""
	}
	//riskJdtoken, err := GetRiskJdToken(client)
	//if err != nil {
	//	return "", err
	//}

	encryptedUsername, encryptedPassword, err := self.getMbEncryptedInfo(rsaString)
	if err != nil {
		server.Logger.Error(err)
		return ""
	}

	encryptedUsername = url.QueryEscape(encryptedUsername)
	encryptedPassword = url.QueryEscape(encryptedPassword)
	resp, err = self.doMbLogin(client, encryptedUsername, encryptedPassword, sToken, dat, wlfstkDatk, loginUrl)
	if err != nil {
		server.Logger.Error(err)
		return ""
	}
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		server.Logger.Error(err)
		return ""
	}
	self.activeSid(client, sid)
	for _, v := range resp.Cookies() {
		if v.Name == "pt_key" {
			server.Logger.Info("updated MB cookie")
			return "pt_key=" + v.Value + ";sid=" + sid + ";"
		}
	}
	return ""
}

func (self *CookieJd) isAliveMbCookie() bool {
	client := self.newClient()
	req, _ := http.NewRequest("GET", "https://home.m.jd.com/myJd/newhome.action", nil)

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	req.Header.Set("Cookie", self.cookies["MB"])
	resp, err := client.Do(req)
	if err != nil {
		server.Logger.Error(err)
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

//登录erp
func (self *CookieJd) loginERP(client *http.Client) error {
	urlStr := "https://ssa.jd.com/sso/login?ReturnUrl=http%3A%2F%2Ferp.jd.com%2F"
	urlValues := &url.Values{
		"username": {self.erpUser},
		"password": {self.erpPass},
	}
	req, _ := http.NewRequest("POST", urlStr, strings.NewReader(urlValues.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// 测试
	//	transport := new(http.Transport)
	//	parsedProxyUrl, _ := url.Parse("http://127.0.0.1:8080")
	//	transport.Proxy = http.ProxyURL(parsedProxyUrl)
	//	self.client.Transport = transport
	// 测试

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
func (self *CookieJd) makeMultipart() (*bytes.Buffer, string) {
	var body = new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("styled_file", "pin.txt")
	part.Write([]byte(self.pin))
	writer.WriteField("token", "6yhn$TGB")
	writer.Close()
	return body, writer.FormDataContentType()
}

func (self *CookieJd) getPcCookie() string {
	server.Logger.Info("updating PC cookie")
	client := self.newClient()
	err := self.loginERP(client)
	if err != nil {
		server.Logger.Error(err)
		return ""
	}
	urlStr := "http://account-helpers.jd.com/tools/customCookie"
	body, contentType := self.makeMultipart()
	req, _ := http.NewRequest("POST", urlStr, body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "text/html")
	resp, err := client.Do(req)
	if err != nil {
		server.Logger.Error(err)
		return ""
	}
	cookie, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		server.Logger.Error(err)
		return ""
	}
	server.Logger.Info("updated PC cookie")
	return "thor=" + strings.TrimSpace(string(cookie)) + ";"
}

//cookie是否存活
func (self *CookieJd) isAlivePcCookie() bool {
	client := self.newClient()
	req, _ := http.NewRequest("GET", "https://home.jd.com", nil)
	req.Header.Add("Cookie", self.cookies["PC"])
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

func (self *CookieJd) verifyMbCookie(errInfo string) bool {
	if self.isAliveMbCookie() {
		return true
	}
	server.Logger.Error("Mb cookie is not alive:" + errInfo)
	return false
}

func (self *CookieJd) verifyPcCookie(errInfo string) bool {
	if self.isAlivePcCookie() {
		return true
	}
	server.Logger.Error("PC cookie is not alive:" + errInfo)
	return false
}

func (self *CookieJd) verifyCookie(errInfo string) bool {
	pcValid := self.verifyPcCookie(errInfo)
	mbValid := self.verifyMbCookie(errInfo)
	return pcValid && mbValid
}

func (self *CookieJd) generateCookie() bool {
	self.cookies["MB"] = self.getMbCookie()
	self.cookies["PC"] = self.getPcCookie()
	self.ckUpdateTime = time.Now()
	return self.verifyCookie("Generate Cookie")
}

//返回结果：是否更新成功，是否真实更新
func (self *CookieJd) updateMbCookie(force bool) (bool, bool) {
	//只有真正更新了M端Cookie才会更新sidUpdateTime
	if force {
		self.cookies["MB"] = self.getMbCookie()
		self.sidUpdateTime = time.Now()
	} else {
		if !self.isAliveMbCookie() {
			self.cookies["MB"] = self.getMbCookie()
			self.sidUpdateTime = time.Now()
		} else {
			//cookie有效，不需要真实更新
			return true, false
		}
	}
	self.ckUpdateTime = time.Now()
	return self.verifyMbCookie("Update Mobile Cookie"), true
}

//返回结果：是否更新成功，是否真实更新
func (self *CookieJd) updatePcCookie(force bool) (bool, bool) {
	if force {
		self.cookies["PC"] = self.getPcCookie()
	} else {
		if !self.isAlivePcCookie() {
			self.cookies["PC"] = self.getPcCookie()
		} else {
			//cookie有效，不需要真实更新
			return true, false
		}
	}
	self.ckUpdateTime = time.Now()
	return self.verifyPcCookie("Update PC Cookie"), true
}

func (self *CookieJd) updateAllCookie(force bool) (bool, bool) {
	pcValid, pcRealdUpdate := self.updatePcCookie(force)
	mbValid, mbRealdUpdate := self.updateMbCookie(force)
	return pcValid && mbValid, pcRealdUpdate && mbRealdUpdate
}

//force： 是否强制更新
//是否有效cookie， 是否真实更新
func (self *CookieJd) updateCookie(force bool) (bool, bool) {
	sidUpdateSucc := true //更新sid的策略
	mbHasUpdate := false
	sidRealUpdate := false
	ckRealUpdate := false
	var ckUpdateSucc bool
	//每50分钟强制更新一次Mb Cookie
	if int(time.Now().Sub(self.sidUpdateTime).Minutes()) >= 50 {
		sidUpdateSucc, sidRealUpdate = self.updateMbCookie(true)
		mbHasUpdate = sidUpdateSucc
	}
	//如果已经更新过mobile端cookie，那么只需要更新PC端Cookie
	if mbHasUpdate {
		ckUpdateSucc, ckRealUpdate = self.updatePcCookie(force)
	} else {
		ckUpdateSucc, ckRealUpdate = self.updateAllCookie(force)
	}
	return sidUpdateSucc && ckUpdateSucc, sidRealUpdate || ckRealUpdate
}
func (self *CookieJd) buildCookie() string {
	cookieString := "pin=" + self.pin + ";" + "pt_pin=" + self.pin + ";"
	for _, v := range self.cookies {
		cookieString += v
	}
	return cookieString
}

//cookie需要多长时间刷新一次
func (self *CookieJd) getRefreshPeriod() int {
	return self.refreshMinute
}

//最后一次更新时间
func (self *CookieJd) getUpdateTime() time.Time {
	return self.ckUpdateTime
}
func (self *CookieJd) flush() {
	for k, _ := range self.cookies {
		self.cookies[k] = ""
	}
}
