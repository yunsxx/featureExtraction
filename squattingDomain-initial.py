import pandas as pd

data = pd.read_csv("TypoDomains.csv")

data = data[['domain','score']]
data.insert(2, 'label', -1)


def labeling(score):
    if score > 54:
        return 1
    else:
        return 0

data['label'] = data['score'].apply(lambda i : labeling(i))

data.insert(3, "targetBrand", "")
# 0 ~ 249 google
# 250 ~ 518 facebook
# 519 ~ 834 microsoft
# 835 ~ 1043 apple
# 1044 ~ 1323 wellsfargo
# 1324 ~ 1605 amazon
# 1606 ~ 1799 walmart
# 1800 ~ 1987 roblox
# 1988 ~ 2214 linkedin
# 2215 ~ 2442 homedepot

for i in range(len(data)):
    if i >= 0 and i <= 249:
        data.at[i, "targetBrand"] = "google.com"
    elif i > 249 and i < 519:
        data.at[i, "targetBrand"] = "facebook.com"
    elif i > 518 and i < 835:
        data.at[i, "targetBrand"] = "microsoft.com"
    elif i > 834 and i < 1044:
        data.at[i, "targetBrand"] = "apple.com"
    elif i > 1043 and i < 1324:
        data.at[i, "targetBrand"] = "wellsfargo.com"
    elif i > 1323 and i < 1606:
        data.at[i, "targetBrand"] = "amazon.com"
    elif i > 1605 and i < 1800:
        data.at[i, "targetBrand"] = "walmart.com"
    elif i > 1799 and i < 1988:
        data.at[i, "targetBrand"] = "roblox.com"
    elif i > 1987 and i < 2215:
        data.at[i, "targetBrand"] = "linkedin.com"
    elif i > 2214 and i < 2443:
        data.at[i, "targetBrand"] = "homedepot.com"


import re

def strToToken(tld):
    if type(tld) == int:
        return 0
    
    token = ''
    for ch in tld:
        token += str(ord(ch))
        
    return token


def length(domain):
    return len(domain)


def digit(domain):
    count = 0
    for i in domain:
        if i.isdigit():
            count = count + 1
    return count


def hyphen(domain):
    hyp = len(re.findall("-", domain))
    return hyp


def dotCount(domain): 
    dot = len(re.findall(r"\.", domain))
    return dot



def subDomain(domain): 
    sub = len(re.findall(r"\.", domain)) - 1 
    return sub



def diffLength(domain):
    original = len(data[data['domain'] == domain].targetBrand.values[0])
    return len(domain) - original



def checkDigit(domain):
    for ch in domain:
        if ch.isdigit():
            return 1 

    return 0 


def checkAddAlpha(domain):
    original = data[data['domain'] == domain].targetBrand.values[0]
    
    if len(domain) > len(original):
        for ch in domain:
            if ch.isdigit():
                return 0
        return 1
    else:
        return 0
    

def ExtractWord(domain):
    if len(re.findall(r"\.", domain)) > 1:
        return 0
    
    original = data[data['domain'] == domain].targetBrand.values[0]
    original = re.split(r"\.", original)[-2]
    
    domain = re.split(r"\.", domain)[-2] 
    result = domain.replace(original,"") 
    
    if (result == domain) | (result == '') | (len(result) <= 1): 
        return 0
    
    return strToToken(result)


def checkWord(word): # ExtracWord result로 실행
    if len(str(word)) >= 2:
        return 1
    return 0


def tldLength(domain):
    domains = re.split(r"\.", domain)
    tld = domains[-1]
    return len(tld)


def ExtractTld(domain):
    domains = re.split(r"\.", domain)
    tld = domains[-1]
    return strToToken(tld)


def tailOrHead(domain):
    original = data[data['domain'] == domain].targetBrand.values[0]
    original = re.split(r"\.", original)[-2] # google.com => google
    domain = re.split(r"\.", domain)[-2] # google0.com => google0
    
    result = domain.replace(original,"") # googel0 exp(google) => 0 :: addition의 경우에만 결과가 나옴 
    
    if(len(result) == 1):
        return 1
    else:
        return 0


from collections import Counter

def checkCharset(domain):
    a1 = []
    a2 = []
    original = data[data['domain'] == domain].targetBrand.values[0]
    
    original = re.split(r"\.", original)[-2] # tld는 제외
    domain = re.split(r"\.", domain)[-2]
    
    for ch in domain:
        a2.append(ch)
        
    for ch in original:
        a1.append(ch)
    
    count_array1 = dict(sorted(Counter(a1).items()))
    count_array2 = dict(sorted(Counter(a2).items()))
    
    
    if (count_array1 == count_array2):
        return 1
    else:
        return 0


def checkBit(domain):
    a1 = []
    a2 = []
    original = data[data['domain'] == domain].targetBrand.values[0]
    
    original = re.split(r"\.", original)[-2] # tld 제외
    domain = re.split(r"\.", domain)[-2]
    
    
    for ch in domain:
        a2.append(ch)
        
    for ch in original:
        a1.append(ch)
        
    count_array1 = dict(sorted(Counter(a1).items()))
    count_array2 = dict(sorted(Counter(a2).items()))
    
    if ((len(domain) == len(original)) & (count_array1 != count_array2)):
        return 1
    else:
        return 0


from itertools import groupby

def checkRepetition(domain):
    original = data[data['domain'] == domain].targetBrand.values[0]
    original = re.split(r"\.", original)[-2] # tld 제외
    domain = re.split(r"\.", domain)[-2]
    
    original_char_set = []
    domain_char_set = []
    repetition_char = []
    
    for ch in original:
        original_char_set.append(ch)
    
    for ch in domain:
        domain_char_set.append(ch)
    
    if len(domain_char_set) <= len(original): # repetition의 경우 domain_char_set 길이가 더 긺. 
        return 0
    
    repetition_char = domain_char_set
    
    
    for index in range(len(original_char_set)):
        if original_char_set[index] in domain_char_set:
            repetition_char.remove(original_char_set[index])
    
    repetition_char = repetition_char[0]
    
    domain_repetition_cnt = []
    original_repetition_cnt = []
    
    for ch, cntCh in groupby(domain):
        if ch == repetition_char:
            domain_repetition_cnt.append(len(list(cntCh)))
    
    for ch, cntCh in groupby(original):
        if ch == repetition_char:
            original_repetition_cnt.append(len(list(cntCh)))
        
    if (len(original_repetition_cnt) != len(domain_repetition_cnt)): # 구한 list 길이가 다르면 repetition 경우가 아님 
        return 0
    
    for i in range(len(domain_repetition_cnt)):
        if (domain_repetition_cnt[i] == (original_repetition_cnt[i] + 1)):
            return 1
        else:
            continue
    
    return 0
    

def checkVowelset(domain):
    original = data[data['domain'] == domain].targetBrand.values[0]
    original = re.split(r"\.", original)[-2]
    domain = re.split(r"\.", domain)[-2]
    
    a1 = ''
    a2 = ''
    original_vowel_index = []
    domain_vowel_index = []
    
    for ch in range(len(original)):
        if original[ch] in ['a','e','i','o','u']:
            a1 += original[ch]
            original_vowel_index.append(1)
        else:
            original_vowel_index.append(0)
    
    for ch in range(len(domain)):
        if domain[ch] in ['a','e','i','o','u']:
            a2 += domain[ch]
            domain_vowel_index.append(1)
        else:
            domain_vowel_index.append(0)
    
    
    if (len(original) == len(domain)) & (a1 != a2) & (len(a1) == len(a2)) & (domain_vowel_index == original_vowel_index): # vowel swap만, addition은 제외
        return 1
    else:
        return 0

def expectType(row):
    if ((row.tailOrHead == 1) & (row.diffLength == 1) & (row.checkAddAlpha == 1)) | ((row.tailOrHead == 1) & (row.diffLength == 1) & (row.checkDigit == 1)):
        return 'addition'
    if ((row.diffLength == -1) & (row.tldLength == 3)):
        return 'omission'
    if ((row.diffLength == 0) & (row.targetBrand != row.domain) & (row.checkCharset == 0) & (row.checkBit == 1) & (row.checkVowelset == 0)):
        return 'replacement'
    if ((row.tldLength != 3) | (str(row.ExtractTld) != strToToken('com'))):
        return 'tldswap'
    if ((row.checkVowelset == 1) & (row.diffLength == 0)):
        return 'vowelswap'
    if ((row.diffLength == 0) & (row.targetBrand != row.domain) & (row.checkCharset == 1)):
        return 'transposition'
    if ((row.diffLength >= 1) & (row.hyphen == 1) & (row.checkWord == 0)):
        return 'hyphenation'
    if ((row.diffLength >= 2) & (row.checkWord == 1)):
        return 'dictionary'
    if ((row.diffLength == 1) & (row.checkRepetition == 1)):
        return 'repetition'
    if (((row.tailOrHead == 0) & (row.diffLength == 1) & (row.checkAddAlpha == 1) & (row.subDomain == 0)) | ((row.tailOrHead == 0) & (row.diffLength == 1) & (row.checkDigit == 1)  & (row.subDomain == 0))):
        return 'insertion'
        
    return 'dotsquatting'
