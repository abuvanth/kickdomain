'''import dns.resolver
answer=dns.resolver.query("support.freshdesk.com", "CNAME")
for i in answer:
    cname=i
print i'''
from kickdomain import *

print(takeover_check(['app.weeschool.com']))