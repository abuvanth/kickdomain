import requests,re,sys,argparse

csrftoken=r'[a-zA-Z0-9]{32}'
def finddomains(target):
    geturl=requests.get('https://dnsdumpster.com/') 
    gettoken=re.findall(csrftoken,geturl.content)
    cookie=geturl.headers['Set-Cookie']
    getcontents=requests.post('https://dnsdumpster.com/',data={'csrfmiddlewaretoken':gettoken[0],'targetip':target},headers={'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:66.0) Gecko/20100101 Firefox/66.0 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8','Referer':'https://dnsdumpster.com/','Cookie':cookie}).content
    subdomains=re.findall(r'[a-zA-Z0-9\.\-]+\.'+target,getcontents)
    return subdomains
if __name__=='__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True,help="Please enter target Url  without http or https")
    args = vars(ap.parse_args())
    for domain in finddomains(args['url']):
        print(domain)