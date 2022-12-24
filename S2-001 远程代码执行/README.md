ThinkPHP是一款运用极广的PHP开发框架。 其5.0.23以前的版本中,获取method的方法中没有正确处理方法名, 导致攻击者可以调用Request类任意方法并构造利用链，从而导致RCE

单个检测：python3 .\CVE-2018-20062-POC.py -t "http://0.0.0.0:1234/"
批量检测：python3 .\CVE-2018-20062-POC.py -f "url.txt"
漏洞利用：./CVE-2018-20062-EXP 
