#coding:utf-8
import sys
import time
import re
import telnetlib

def telnet(ip, port, user, pass_):
	try:
		tn = telnetlib.Telnet(ip,int(port),5)
		tn.set_debuglevel(3)
		time.sleep(0.5)
		os = tn.read_some()
	except Exception,e:
		print e
		print "stop!"
		return 3
	user_match="(?i)(login|user|username)"
	pass_match='(?i)(password|pass)'
	login_match='#|\$|>'
	if re.search(user_match,os):
		try:
			tn.write(str(user)+'\r\n')
			tn.read_until(pass_match,timeout=2)
			tn.write(str(pass_)+'\r\n')
			login_info=tn.read_until(login_match,timeout=3)
			tn.close()
			if re.search(login_match,login_info.replace(pass_,"")):
				print "1vul!"
				return "username:%s,password:%s" % (user,pass_)
		except Exception,e:
			print "stop!"
			print e
			pass
	else:
		try:
			info=tn.read_until(user_match,timeout=2)
		except Exception,e:
			print e
			print "stop!"
			return 3
		if re.search(user_match,info):
			try:
				tn.write(str(user)+'\r\n')
				tn.read_until(pass_match,timeout=2)
				tn.write(str(pass_)+'\r\n')
				login_info=tn.read_until(login_match,timeout=3)
				tn.close()
				if re.search(login_match,login_info.replace(pass_,"")):
					print "2vul!"
					return "username:%s,password:%s" % (user,pass_)
			except Exception,e:
				print e
				print "stop!"
				pass
		elif re.search(pass_match,info):
			tn.read_until(pass_match,timeout=2)
			tn.write(str(pass_)+'\r\n')
			login_info=tn.read_until(login_match,timeout=3)
			tn.close()
			if re.search(login_match,login_info.replace(pass_,"")):
				print "3vul!"
				return "password:%s" % (pass_)

if __name__ == "__main__":
	telnet(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
