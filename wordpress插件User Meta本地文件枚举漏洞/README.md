
wordpress插件User Meta本地文件枚举漏洞（CVE-2022-0779）
此漏洞只能检测某文件是否存在，并不能读取文件的内容
pf_nonce的值需要到页面源码中找

python3 CVE-2022-0779-POC.py -t <target> -p <pf_nonce>
-t url: 目标地址
-pf pf_nonce: 源代码中的pf_nonce
-h help: 帮助
python3 CVE-2022-0779-EXP.py -t <target> -p <pf_nonce> -f <filename>
-t url: 目标地址
-pf pf_nonce: 源代码中的pf_nonce
-f filename: 要读取的文件名
-h help: 帮助
