package main

import (
	"fmt"
	"net/url"
	"time"

	"zeroScannerGo/engine"
	"zeroScannerGo/engine/lib/zhttp"
)

var (
	InitDnsCache = zhttp.SetDnsCache
)

func Verify(params engine.Params) (result engine.Result) {
	resp, err := zhttp.Get(params.ParsedTarget.String(), &zhttp.RequestOptions{
		RequestTimeout:     time.Second * 5,
		DialTimeout:        time.Second * 5,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	defer resp.Close()
	fmt.Println(params.Target)
	fmt.Println(params.ParsedTarget.String())
	fmt.Println(resp.RawRequest())
	return
}

func main() {
	params := engine.Params{}
	params.Method = "GET"
	params.Target = "http://search.yhd.com/c0-0/mbname-b/a-s1-v4-p1-price-d0-f0b-m1-rt0-pid-mid0-color-size-kasd?crumbKeyword=xxxxxxdwu%2522vB"
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget
	params.Cookie = "pin=waimianyougesongshu;pt_pin=waimianyougesongshu;pt_key=AAFavMaBADB6IryAuSCc8IVl2SQbF0jYWGFjEDYx0l99qPIMMhVeo8YtHEN7ZE0TzKGBhADQ8Ek;sid=a7d7a256a18f7242babc9516092a7c6e;thor=884D10118748D180567B037F55C4568F7C4E96C36F74BA194212867475A78225225F8650048069E8E545268398528FB9A0DA543A29652D7F65F1DC8F08028D9D1334B999CB44BB98BFCF8FDF79FCE8418242953978AB36C67855E209172CA17685D839176A710265AAEC63831F4565ECE5876A16270AF28D2B202A3085AF6997042DE95D1850F204F23CEAB3D09E56FB22DE58FCCA7E1147CBD029F42D398092;"

	result := Verify(params)
	fmt.Println("result.Vul:", result.Vul)
	fmt.Println("result.VulUrl:", result.VulUrl)
	fmt.Println("result.VulInfo:", result.VulInfo)
}
