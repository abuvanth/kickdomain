import kickdomain

f=['avira.com','att.com']

for i in f:
    result=kickdomain.getSubdomains(i)
    print result
