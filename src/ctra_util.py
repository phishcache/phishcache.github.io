# -*- coding: utf8 -*-
# cyaddr util v1 20150408 by ykx10
import worker_pgdb
import re, json, time
from datetime import timedelta
from datetime import datetime
from psycopg2 import TimestampFromTicks

def get_conf(conf_type):
	# read conf file and return config  --- not yet need to modification
	result = 'Error : Config'
	try:
		rf = open('conf/ctra.conf','r')
		while 1:
			rline = rf.readline()
			if not rline: break
			if rline.strip()[0]=="#": continue
			rcol = rline.split("=",1)
			if len(rcol)!=2: continue
			if rcol[0]==conf_type:
				returnstr = rcol[1]
	except:
		print "ERROR"
	return result

def identify(target):
	if not target: return 'None'
	#url, ip, domain, email, error=None
	typestr = 'None'
	# find url pick up
	if target[:4]=='http':
		typestr = "url"
	# find IP by regular exp
	elif re.match("(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",target):
		typestr = "ip"
	# find email by regular exp
	elif re.match("([a-z0-9_\.-]+)@([\da-z\.-]+)\.([a-z\.]{2,6})",target):
		typestr = "email"
	# find mac addr by regular exp
	elif re.match("([0-9a-fA-F][0-9a-fA-F]:){5}([0-9a-fA-F][0-9a-fA-F])",target):
		typestr = "mac"
	# find domain/url by regular exp
	elif re.match("(([\w]+:)?//)?(([\d\w]|%[a-fA-f\d]{2,2})+(:([\d\w]|%[a-fA-f\d]{2,2})+)?@)?([\d\w][-\d\w]{0,253}[\d\w]\.)+[\w]{2,4}(:[\d]+)?(/([-+_~.\d\w]|%[a-fA-f\d]{2,2})*)*(\?(&?([-+_~.\d\w]|%[a-fA-f\d]{2,2})=?)*)?(#([-+_~.\d\w]|%[a-fA-f\d]{2,2})*)?",target):
		# cutting up possible dirty string or list
		js_result = json.loads(get_mainserver(target))
		if js_result.has_key('error'):return js_result
		msrv = js_result['mainsrv']
		itarget = target.replace(msrv,'')
		if len(itarget.replace('/',''))>0:
			typestr = "url"
		else:
			typestr = "domain"
	if typestr=='None' and re.match("(([\d\w]|%[a-fA-f\d]{2,2})+(:([\d\w]|%[a-fA-f\d]{2,2})+)?@)?([\d\w][-\d\w]{0,253}[\d\w]\.)+[\w]{2,4}(:[\d]+)?(/([-+_~.\d\w]|%[a-fA-f\d]{2,2})*)*(\?(&?([-+_~.\d\w]|%[a-fA-f\d]{2,2})=?)*)?(#([-+_~.\d\w]|%[a-fA-f\d]{2,2})*)?",target):
		typestr = "domain"
	return typestr

def get_mainserver(target):
	# find main server
	itarget = target.replace("http://",'').replace("https://",'')+"/"
	itarget = itarget[:itarget.find('/')]
	return "{\"reqobj\":\""+target+"\",\"mainsrv\":\""+itarget+"\"}"

def get_cyaddr(target, typestr=''):
	# check exist cyaddr
	target = target.replace("[",'').replace("]",'').replace(",",' ').replace(";",' ').replace("\"",'').replace("`",'').replace("'",'')
	querystr = "SELECT DISTINCT cyaddr_id FROM ctra.cyaddr_lib WHERE cyaddr=\'"+target+"\'"
	result = worker_pgdb.query(querystr)
	if len(result)<3:
		return '0'
	js_rst = json.loads(result)
	if js_rst.has_key('error'): return '0'
	icyaddr_id = js_rst['result'].split("\n")[0]
	
	# insert NEW record
	if len(icyaddr_id) <= 0:
		print "*NEW cyaddr :"+target
		if typestr=='':
			itype = identify(target)
		else:
			itype = typestr
		querystr = "INSERT INTO ctra.cyaddr_lib VALUES (DEFAULT, '"+itype+"', '"+target+"') RETURNING cyaddr_id"
		js_rst = json.loads(worker_pgdb.query(querystr))
		if js_rst.has_key('error'): return '0'
		icyaddr_id = js_rst['result'].split("\n")[0]
	# return cyaddr_id
	icyaddr_id = ''.join(str(icyaddr_id))
	icyaddr_id = icyaddr_id.split(",")[0].replace("[",'').replace("]",'').replace("(",'').replace(")",'').replace("L",'')
	return icyaddr_id

def link_cyaddr(from_cyaddr, to_cyaddr, ltypestr):
	# get cyaddr(from, to)
	fromid = get_cyaddr(from_cyaddr)
	toid = get_cyaddr(to_cyaddr)
	if fromid == '0' or toid == '0':
		return 0
	# make insert query
	querystr = "INSERT INTO ctra.linkage_info VALUES (DEFAULT, "+str(TimestampFromTicks(time.time()))+","+str(fromid)+","+str(toid)+",'"+ltypestr+"') RETURNING link_id"
	js_result = json.loads(worker_pgdb.query(querystr))
	if js_result.has_key('error'):return js_result
	return js_result

# Return json when fresh exist
def get_fresh_exist(target, hour=1):
	returnstr = ''
	# get max req_id, whois_dt
	querystr = "SELECT req_id, whois_dt FROM ctra.whois_record WHERE whois_dt = (SELECT MAX(whois_dt) FROM ctra.whois_record WHERE object='"+target+"')"
	js_result = json.loads(worker_pgdb.query(querystr))
	# if query error, no fresh exist
	if js_result.has_key('error'): return "No Exist"
	resval = js_result['result']
	# if record is null, no fresh exist
	if not resval: return "No Exist"
	
	# extract info exist record
	maxrow = resval.split("\n")[0]
	reqid = maxrow.split(",")[0].strip("(")
	timestr = maxrow.split("(",2)[2].strip(")").strip(" ")
	try:
		gap = datetime.now() - datetime.strptime(timestr, "%Y, %m, %d, %H, %M, %S")
	except:
		gap = timedelta(hours=9999999)
	# no fresh
	if gap > timedelta(hours=hour):
		return "No Exist"

	# Get JSON
	querystr = "SELECT * FROM ctra.whois_record WHERE req_id="+str(long(reqid))
	jsliststr = worker_pgdb.getjson(querystr)
	jsonpack = []
	if len(jsliststr)<5: return "No Exist"
	for rec in jsliststr.split("(*&^"):
		rec = rec.encode('utf8')
		jsonpack.append(rec[2:-3].replace("\\\\n",'\\n').replace("\\\'","\'").replace("\\\"","\"").replace("\\x",'!!x'))
	return jsonpack
