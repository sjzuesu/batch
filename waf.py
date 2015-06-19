import random
import string
import telnetlib
import thread
import threading
import os	

actions = ['alert','deny']
severitys = ['low','medium','high']
vdoms=['root','vdom1','vdom2']
vdom_intf={'root':'port5','vdom1':'port6','vdom2':'port7'}
Host = '10.0.110.203' 
username = 'admin'
password = ''
finish = '#'

def open_telnet(Host, username, pwd, finish):
    tn = telnetlib.Telnet(Host, port=23, timeout=10)
    tn.set_debuglevel(0)
    tn.read_until('login:')
    tn.write(username + '\n')
    tn.read_until('Password:')
    tn.write(pwd + '\n')
    print tn.read_until(finish)
    return tn

def send(telnet_obj,string,thread_id=0,promt='#'):
    telnet_obj.write(string+'\n')
    print 'Thread(%s)===>%s' % (thread_id,telnet_obj.read_until(promt))
    
def random_chars(size=10):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))

def conf_access_rule(size=1):
    commands=[]
    commands.append('config  url-access-rule')
    i=0
    while i<size:
	i+=1
        commands.append('edit %s' % i)
        commands.append('set action ' + random.choice(actions))
        commands.append('set severity ' + random.choice(severitys))
        commands.append('set url-pattern ' + random_chars(20))
        commands.append('next')
    commands.append('end')
    return commands
    
def conf_extension_file(size=1):
    commands=[]
    commands.append('config  file-extension-rule')
    i=0
    while i<size:
	i+=1
        commands.append('edit %s' % i)
        commands.append('set action ' + random.choice(actions))
        commands.append('set severity ' + random.choice(severitys))
        commands.append('set file-extension-pattern ' + random_chars(19))
        commands.append('next')
    commands.append('end')
    return commands
    
def conf_url_protection(size=1,extension_size=1,access_fize=1):
    commands=[]
    commands.append('config security waf url-protection')
    i = 0
    while i<size:
        i+=1
        commands.append('edit %s' % i)
	commands += conf_access_rule(access_fize)
	commands += conf_extension_file(extension_size)	
        commands.append('next')
    commands.append('end')
    return commands

def conf_sql_xss_inject_detect(size=1):
    i = 0
    commands=[]
    commands.append('config security waf heuristic-sql-xss-injection-detection')
    while i<size:
        i+=1
        commands.append('edit %s' % i) 
        commands.append('set sql-injection-detection enable')
        commands.append('set cookie-sql-injection-detection enable')
        commands.append('set referer-sql-injection-detection enable')
        commands.append('set uri-sql-injection-detection enable')
        commands.append('set body-sql-injection-detection enable')
        commands.append('set sql-injection-action ' + random.choice(actions))
        commands.append('set sql-injection-severity ' + random.choice(severitys))
        commands.append('set xss-detection enable')
        commands.append('set cookie-xss-detection enable')
        commands.append('set referer-xss-detection enable')
        commands.append('set uri-xss-detection enable')
        commands.append('set body-xss-detection enable')
        commands.append('set xss-action ' + random.choice(actions))
        commands.append('set xss-severity ' + random.choice(severitys))
        commands.append('next')
    commands.append('end')
    return commands

def subconf_req_method_rule(size=1):
    i=0
    commands=[]
    commands.append('config  request-method-rule')
    while i<size:
        i+=1 
        commands.append('edit %s' % i)
        commands.append('set method CONNECT DELETE GET HEAD OPTIONS OTHERS POST PUT TRACE')
        commands.append('set action ' + random.choice(actions))
        commands.append('set severity ' + random.choice(severitys))
        commands.append('next')
    commands.append('end')
    return commands


def subconf_res_code_rule(size=1):
    i=0
    commands=[]
    commands.append('config  response-code-rule ')
    while i<size:
        i+=1 
        commands.append('edit %s' % i)
        code_min = random.choice(range(400,595))
        code_max = random.choice(range(code_min,599))
        commands.append('set code-min %s' % code_min)
        commands.append('set code-max %s' % code_max)
        commands.append('set action ' + random.choice(actions))
        commands.append('set severity ' + random.choice(severitys))
        commands.append('next')
    commands.append('end')
    return commands
  

def conf_http_constraint(size=1,code_size=1,method_size=1): 
    i=0
    commands=[]
    commands.append('config security waf http-protocol-constraint ')
    while i<size: 
        i+=1
        commands.append('edit %s' % i)
        commands.append('set max-uri-length %s' % random.choice(range(1,8193)))
        commands.append('set max-uri-length-action ' + random.choice(actions))
        commands.append('set max-uri-length-severity ' + random.choice(severitys))
        commands += subconf_req_method_rule(method_size)
        commands += subconf_res_code_rule(code_size)
        commands.append('next')
    commands.append('end')
    return commands


def conf_web_sig(size=1):
    i=0
    commands=[]
    commands.append('config security waf web-attack-signature ')
    while i<size:
        i+=1
        commands.append('edit %s' % i)
        commands.append('set request-body-detection %s' % random.choice(['enable','disable']))
        commands.append('set response-body-detection %s' % random.choice(['enable','disable']))
        commands.append('set high-severity-action %s' % random.choice(actions))
        commands.append('set medium-severity-action %s' % random.choice(actions))
        commands.append( 'set low-severity-action %s' % random.choice(actions))
	commands.append('set status %s' % random.choice(['enable','disable']))	
        commands.append('next')
    commands.append('end')
    return commands

def conf_waf_profile(size=1):
    i=0
    commands=[]
    commands.append('config security waf profile')
    while i<size:
        i+=1
        commands.append('edit %s' % i)
        commands.append('set description %s' % i)
        commands.append('set heuristic-sql-xss-injection-detect %s' % random.choice(range(1,257)))
        commands.append('set http-protocol-constraint %s' % random.choice(range(1,257)))
        commands.append('set url-protection %s' % random.choice(range(1,257)))
        commands.append('set web-attack-signature %s' % random.choice(range(1,257)))
        commands.append('set http-header-cache %s' % random.choice(['enable','disable']))
        commands.append('next')
    commands.append('end')
    return commands

def conf_pool4(pool_name='1'):
    commands=[]
    commands.append('config load-balance pool')
    commands.append('edit %s' % pool_name)
    commands.append('config pool_member')
    j=0
    while j<3:
	j+=1
	commands.append('edit %s' % j)
	commands.append('set ip 1.1.1.%s' % j)
	commands.append('next')
    commands.append('end')
    commands.append('next')
    commands.append('end')
    return commands    
def conf_vs(size=1,intf='port1',rs='1',vs_type='l7-load-balance'):
    i=0
    clis=[]
    clis += conf_pool4(rs)
    clis.append('config load-balance virtual-server')
    while i<size:
        i+=1
        clis.append('edit %s' % i)
        clis.append('set type %s' % vs_type)
        clis.append('set waf-profile %s' % random.choice(range(1,252)))
        clis.append('set load-balance-pool %s' % rs)
        clis.append('set interface %s' % intf)
        clis.append('set load-balance-method LB_METHOD_ROUND_ROBIN')
        clis.append('set load-balance-profile LB_PROF_HTTPS')
        clis.append('set ip 10.202.10.%s' % (i))
	clis.append('set multi-process 15')
        clis.append('next')
    clis.append('end')
    return clis

def send_list(telnet_obj,lis,thread_id=0,prompt='#'):
    for ele in lis:
	send(telnet_obj,ele,thread_id,prompt)

	
class send_thread(threading.Thread):
    def __init__(self,telnet_obj,cmd_list,thread_id=0,prompt='#'):
	threading.Thread.__init__(self)
	self.telnet_obj = telnet_obj
	self.cmd_list = cmd_list
	self.thread_id = thread_id
	self.prompt = prompt
	
    def run(self):
	print 'Thread(%s) started...' % self.thread_id
	send_list(self.telnet_obj,self.cmd_list,self.thread_id,self.prompt)
		

if __name__=='__main__':

	#step-1
	cmds_waf_url = conf_url_protection(size=15,extension_size=1,access_fize=1)
	cmds_waf_sql_xss = conf_sql_xss_inject_detect(size=15)
	cmds_waf_http_constraint= conf_http_constraint(size=15,code_size=1,method_size=1)
	cmds_waf_sig = conf_web_sig(size=15)
	#step-2
	cmd2s_waf_url = conf_url_protection(size=10,extension_size=20,access_fize=20)
	cmd2s_waf_http_constraint= conf_http_constraint(size=10,code_size=20,method_size=20)
	#step-3
	cmd3s_waf_profile = conf_waf_profile(size=15)
	#step-4
	#cmd4s_vs = conf_vs(size=250,vdom_intf[vdom])
	
	cmd1s=[cmds_waf_url,cmds_waf_sql_xss,cmds_waf_http_constraint,cmds_waf_sig]
	cmd2s=[cmd2s_waf_url,cmd2s_waf_http_constraint]
	cmd3s=[cmd3s_waf_profile]
	cmds=[cmd1s,cmd2s,cmd3s,'conf_vs']
	#cmds=['conf_vs']
	
	#before vs
	for cmd in cmds:
	    threads=[]
	    telnets=[]
	    for vdom in vdoms:
		for i in range(len(cmd)):
		    tn=open_telnet(Host, username, password, finish)
		    telnets.append(tn)
		    send(tn,'config vdom')
		    send(tn,'edit %s' % vdom)
		    if cmd=='conf_vs':
			threads.append(send_thread(tn,conf_vs(size=15,intf=vdom_intf[vdom]),'%s-%s' % (vdom,i),finish))
			break
		    else:
			threads.append(send_thread(tn,cmd[i],'%s-%s' % (vdom,i),finish))
			
	    for thread in threads:
		thread.start()
	    for thread in threads:
		print '%s joined...' % thread.thread_id
		thread.join()
	    for tn in telnets:
		send(tn,'end')
		tn.close()
