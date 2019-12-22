#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests,re,argparse,os
from colorama import init, Fore, Back, Style
from provider import *
import dns.resolver
import time
import censys.certificates
import censys.ipv4
import censys
sub_regex=r'[a-z0-9\.\-]+\.'
def filter_live(domainlist):
    livedomains=[]
    for i in domainlist:
        try:
            result=scanport(i)
            if len(result)>0 and result[0]!='service down':
                #print(i+' is live')
                livedomains.append(i)
        except:
            #print(i+' is down')
            pass
    return livedomains
def portscan(targets):
    result=[]
    for z in targets:
        r=scanport(z)
        result.append((z,r))
    return result            
def clear_url(target):
	return re.sub('.*www\.','',target,1).split('/')[0].strip()
def remove_duplicate(x):
    return list(dict.fromkeys(x))
def domains_from_censys(domain):
    try:
        censys_id,censys_secret=config.censys_id,config.censys_secret
        if censys_id=='' and censys_secret=='':
            censys_id=os.environ.get('CENSYS_ID','')
            censys_secret=os.environ.get('CENSYS_SECRET','')
        if censys_secret=='':
           print("Censys keys not found")
           return []
        censys_cert = censys.certificates.CensysCertificates(api_id=censys_id,api_secret=censys_secret)
        cert_query = 'parsed.names: %s' % domain
        cert_search_results = censys_cert.search(cert_query, fields=['parsed.names'])
 
        subdomains = []
        for s in cert_search_results:
            subdomains.extend(s['parsed.names'])
 
        return [ subdomain for subdomain in subdomains if  subdomain.endswith(domain) ]
    except censys.base.CensysUnauthorizedException:
        print("Censys keys not found")
        return subdomains
    except censys.base.CensysRateLimitExceededException:
        return [ subdomain for subdomain in subdomains if  subdomain.endswith(domain) ]
def domains_from_dnsdumpster(target):
    try:
       csrftoken=r'[a-zA-Z0-9]{32}'
       geturl=requests.get('https://dnsdumpster.com/') 
       gettoken=re.findall(csrftoken,geturl.content)
       cookie=geturl.headers['Set-Cookie']
       getcontents=requests.post('https://dnsdumpster.com/',data={'csrfmiddlewaretoken':gettoken[0],'targetip':target},headers={'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:66.0) Gecko/20100101 Firefox/66.0 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8','Referer':'https://dnsdumpster.com/','Cookie':cookie}).content
       subdomains=re.findall(sub_regex+target,getcontents)
       return subdomains
    except:
       return []
def domains_from_crt_sh(target):
    subdomains = []
    try:
       req = requests.get("https://crt.sh/?q=%.{d}&output=json".format(d=target))
       for (key,value) in enumerate(req.json()):
           subdomains.append(value['name_value'])
           subdomains = sorted(set(subdomains))
    except:
        pass
    return subdomains
def domains_from_virustotal(target):
    getdomains=requests.get('https://www.virustotal.com/ui/domains/'+target+'/subdomains?limit=40').content
    finddomains=re.findall(sub_regex+target,getdomains)
    return finddomains
def domains_from_shodan(target):
    api_key=config.shodan_api_key
    if api_key=='':
       api_key=os.environ.get('SHODAN_API_KEY','')
    if api_key=='':
        print("shodan api key not found")
        return []
    else:
        getdomains=requests.get('https://api.shodan.io/shodan/host/search?key='+api_key+'&query=ssl:'+target).content
        finddomains=re.findall(sub_regex+target,getdomains)
    return finddomains
def domains_from_bufferover(target):
    getdomains=requests.get('https://dns.bufferover.run/dns?q='+target).content
    finddomains=re.findall(sub_regex+target,getdomains)
    return finddomains
def domains_from_facebook(target):
    access_token=config.fb_access_token
    if access_token=='':
       access_token=os.environ.get('FB_ACCESS_TOKEN','')
    if access_token=='':
        print("fb access token not found")
        return []
    else:
        getdomains=requests.get('https://graph.facebook.com/v3.3/certificates?access_token='+access_token+'&pretty=0&fields=domains&query='+target+'&limit=1000').content
        finddomains=re.findall(sub_regex+target,getdomains)
    return finddomains
def domains_from_findsubdomains(target):
    getdomains=requests.get('https://spyse.com/search/subdomain?q='+target).content
    finddomains=re.findall(sub_regex+target,getdomains)
    return finddomains
def domains_from_threatcrowd(target):
    getdomains=requests.get('https://www.threatcrowd.org/searchApi/v2/domain/report/?domain='+target).content
    finddomains=re.findall(sub_regex+target,getdomains)
    return finddomains
def domains_from_certspotter(target):
    getdomains=requests.get('https://certspotter.com/api/v0/certs?domain='+target).content
    finddomains=re.findall(sub_regex+target,getdomains)
    return finddomains
def getSubdomains(target):
    domainlist=remove_duplicate(domains_from_censys(target)+domains_from_certspotter(target)+domains_from_shodan(target)+domains_from_threatcrowd(target)+domains_from_bufferover(target)+domains_from_findsubdomains(target)+domains_from_facebook(target)+domains_from_crt_sh(target)+domains_from_dnsdumpster(target)+domains_from_virustotal(target))
    return [x.strip('.') for x in domainlist if not x.startswith('*') ]+['app.weeschool.com']
def takeover_check(subdomains,silent=False):
    result=[]
    for subdomain in subdomains:
        try:
           answer=dns.resolver.query(subdomain, "CNAME")
           for i in answer:
               cname=str(i)
        except:
              cname=''
        try:
            data=requests.get('http://'+subdomain,timeout=10).content
        except:
            data=''
        for k in providers.provider:
          init()
          c=False
          r=False
          p=False
          for cn in k['cname']:
             if cname.__contains__(cn):
                c=True
                print('cname match')
          for res in k['response']:
              if data.__contains__(res):
                print('response match')
                r=True
          if c and r:
             break
        if not silent:
           if c and r:
              p=True
              print(Fore.GREEN+subdomain+' is vulnerable to takeover')
              print("CName - "+cname)
           else:
              print(Fore.RED+subdomain+' is not vulnerable to takeover')
        result=result+[(subdomain,p)]
    return result
if __name__=='__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True,help="Please enter target Url  without http or https")
    ap.add_argument("-t", "--takeover", required=False,help="True or False")
    ap.add_argument("-p", "--portscan", required=False,help="True or False")
    args = vars(ap.parse_args())
    if args['url'].startswith('http'):
        print("Enter url without http and www")
        exit()
    domains=getSubdomains(clear_url(args['url']))
    print(clear_url(args['url'])+' has '+str(len(domains))+' unique  subdomains')
    for domain in domains:
        print(domain)
    if args['portscan']:
        for v in portscan(domains):
            print(v[0],v[1])

    if args['takeover']:
       for i in  takeover_check(domains):
           if i[1]:
               print(Fore.GREEN+i[0]+' is vulnerable to takeover')
           else:
               print(Fore.RED+i[0]+' is not vulnerable to takeover')
       
