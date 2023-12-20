#!/usr/bin/env python
# coding: utf-8

# In[1]:


import pandas as pd
data = pd.read_csv('phishing_site_urls.csv')


# In[2]:


data.head()


# In[3]:


rem = {'Label': {'bad': 1, 'good': 0}}

data = data.replace(rem)


# In[4]:


data.Label.value_counts()


# In[5]:


import re 
from urllib.parse import urlparse
from tld import get_tld, is_tld

def process_tld(url):
    try:
        res = get_tld(url, as_object = True, fail_silently=False,fix_protocol=True)
        pri_domain= res.parsed_url.netloc
    except :
        pri_domain= None
    return pri_domain


data['domain'] = data['URL'].apply(lambda i : process_tld(i))


# In[6]:


data.head()


# In[7]:


data = data.dropna(axis=0, how='any', inplace=False)


# In[8]:


data.isnull().sum()


# In[9]:





# In[10]:





# In[11]:


# domain length 
def domainLength(domain):
    length = len(domain)
    return length

data['domainLength'] = data['domain'].apply(lambda i : domainLength(i))


# In[12]:


#domain list 
def getDomainlist(domain):
    if type(domain) == str:
        words = list(re.split(r"\.",domain))
        return words
    else:
        return None


data['domainList'] = data['domain'].apply(lambda i : getDomainlist(i))


# In[13]:


def calculateLength(domains):
    lengthList = []
    for i in domains:        
        lengthList.append(len(i))
    return lengthList

data['lengthList'] = data['domainList'].apply(lambda i : calculateLength(i))


# In[14]:


#node list
def getNodelist(domain):
    NodeList = []
    cur_domain = ""
    count = 0
    
    for i in reversed(domain):
        if i == None:
            continue
        
        if count == 0:
            cur_domain = i
            NodeList.append(cur_domain)
            count += 1
        elif count != 0:
            cur_domain = i + "." + cur_domain
            NodeList.append(cur_domain)
            count += 1
            
    
    return NodeList

data['nodeList'] = data['domainList'].apply(lambda i : getNodelist(i))


# In[15]:


from tld import get_tld, is_tld
import re

def tldList(url):
    tld_list = []
    
    try:
        res = get_tld(url, as_object = True, fail_silently=False, fix_protocol=True)
        pridomain = res.parsed_url
        netpath = pridomain.netloc + pridomain.path
    
        words = netpath.split('/')
    
        for i in words:
            word = re.split(r"\.", i)
        
            for i in range(len(word)):
                if is_tld(word[i]) == True:
                    tld_list.append(word[i])
    except: 
        return 0
    
    return tld_list

data['tldList'] = data['URL'].apply(lambda i : tldList(i))


#tld count
def tldCount(tldlist):
    if type(tldlist) == int:
        return 0
    
    count = len(tldlist)
    return count

data['tldCount'] = data['tldList'].apply(lambda i : tldCount(i))


# In[16]:


def dotCount(domain):
    domainCount = len(re.findall(r"\.", domain))
    return domainCount

data['dotCount'] = data['domain'].apply(lambda i : dotCount(i))


#domain count 
def domainCount(dot):
    return dot+1

data['domainCount'] = data['dotCount'].apply(lambda i : domainCount(i))


# In[17]:


#hyphen
def hyphen(domain):
    hyp = len(re.findall("-", domain))
    return hyp

data['hyphen'] = data["domain"].apply(lambda i : hyphen(i))


#digit
def digits(domain):
    count = 0
    for i in domain:
        if i.isdigit():
            count = count + 1
    return count

data['digit'] = data['domain'].apply(lambda i : digits(i))


# In[18]:


#special_chars
def count_special_chars(domain):
    special_chars = "!@#$%^&*()_+-=[]{};:,.<>/?`~|"
    count = sum(char in special_chars for char in domain)
    return count

data['special_chars'] = data['domain'].apply(lambda i : count_special_chars(i))


# In[19]:


data.tail()


# In[20]:


#ip address 
def have_ip_address(url):
    pattern = r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.' \
              r'([01]?\d\d?|2[0-4]\d|25[0-5])\/)|' \
              r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.' \
              r'([01]?\d\d?|2[0-4]\d|25[0-5])\/)|' \
              r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\/)' \
              r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|' \
              r'([0-9]+(?:\.[0-9]+){3}:[0-9]+)|' \
              r'((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)'

    match = re.search(pattern, url)
    if match:
        return 1
    else:
        return 0

data['having_IP'] = data['domain'].apply(lambda i : have_ip_address(i))


# In[21]:


#maxRatio
def maxRatio(dlength, dlist, dot):    
    dlength = dlength - dot
    
    ratio = round((dlist/dlength), 3)
    return ratio


data.insert(4, 'maxRatio', 0) 
# keyerror 방지. 미리 maxRatio column 생성해두기


# In[22]:


for i in range(len(data)):
    data.iloc[i]['maxRatio'] = maxRatio(data.iloc[i]['domainLength'], max(data.iloc[i]['lengthList']), data.iloc[i]['dotCount'])


# In[23]:


import whois 
import datetime


def age_of_domain(url):
    try:
        print(data.index[data['domain'] == url])
        domain_info = whois.whois(url)
        result = (datetime.datetime.today().year - domain_info.creation_date[0].year) *12 + datetime.datetime.today().month - domain_info.creation_date[0].month
    except:
        return 0
    
    return result


data['age_of_domain'] = data['domain'].apply(lambda i : age_of_domain(i))


# In[24]:


data.head()


# In[25]:


data.to_csv('preprocess_phishing_site_urls.csv', index=False)


# In[ ]:




