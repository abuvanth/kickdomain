#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests,re,argparse,os
from provider import providers,config
import dns.resolver
csrftoken=r'[a-zA-Z0-9]{32}'
def clear_url(target):
	return re.sub('.*www\.','',target,1).split('/')[0].strip()
def remove_duplicate(x):
    return list(dict.fromkeys(x))
def domains_from_dnsdumpster(target):
    geturl=requests.get('https://dnsdumpster.com/') 
    gettoken=re.findall(csrftoken,geturl.content)
    cookie=geturl.headers['Set-Cookie']
    getcontents=requests.post('https://dnsdumpster.com/',data={'csrfmiddlewaretoken':gettoken[0],'targetip':target},headers={'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:66.0) Gecko/20100101 Firefox/66.0 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8','Referer':'https://dnsdumpster.com/','Cookie':cookie}).content
    subdomains=re.findall(r'[a-z0-9\.\-]+\.'+target,getcontents)
    return subdomains
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
    finddomains=re.findall(r'[a-z0-9\-\.]+\.'+target,getdomains)
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
        finddomains=re.findall(r'[a-z0-9\-\.]+\.'+target,getdomains)
    return finddomains
def domains_from_findsubdomains(target):
    getdomains=requests.get('https://findsubdomains.com/subdomains-of/'+target).content
    finddomains=re.findall(r'[a-z0-9\-\.]+\.'+target,getdomains)
    return finddomains
def getSubdomains(target):
    return remove_duplicate(domains_from_findsubdomains(target)+domains_from_facebook(target)+domains_from_crt_sh(target)+domains_from_dnsdumpster(target)+domains_from_virustotal(target))
def takeover_check(subdomains):
    result=[]
    for subdomain in subdomains:
        try:
           answer=dns.resolver.query(subdomain, "CNAME")
           for i in answer:
               cname=str(i)
        except:
              cname=''
        try:
            data=requests.get('http://'+subdomain).content
        except:
            data=''
        pro_list=[]
        res_list=[]
        c=False
        d=False
        p=False
        for k in providers.provider:
            pro_list.append(k['cname'])
            res_list.append(k['response'])
        for t in pro_list:
            for w in t:
                if cname.__contains__(w):
                   c=True
        for s in res_list:
            for f in s:
                if data.__contains__(f):
                    d=True
        if c and d:
            p=True
        result=result+[(subdomain,p)]
    return result
if __name__=='__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True,help="Please enter target Url  without http or https")
    ap.add_argument("-t", "--takeover", required=False,help="True or False")
    args = vars(ap.parse_args())
    if args['url'].startswith('http'):
        print("Enter url without http and www")
        exit()
    domains=getSubdomains(clear_url(args['url']))
    for domain in domains:
        print(domain)
    if args['takeover']:
       for i in  takeover_check(domains):
           if i[1]:
               print(i[0]+' is vulnerable to takeover')
           else:
               print(i[0]+' is not vulnerable to takeover')
       
