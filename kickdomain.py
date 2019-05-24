import requests,re,sys,argparse

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
    subdomains=re.findall(r'[a-zA-Z0-9\.\-]+\.'+target,getcontents)
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
    finddomains=re.findall(r'[a-zA-Z0-9\-\.]+\.'+target,getdomains)
    return finddomains
def getSubdomains(target):
    return remove_duplicate(domains_from_crt_sh(target)+domains_from_dnsdumpster(target)+domains_from_virustotal(target))
if __name__=='__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True,help="Please enter target Url  without http or https")
    args = vars(ap.parse_args())
    for domain in getSubdomains(clear_url(args['url'])):
        print(domain)