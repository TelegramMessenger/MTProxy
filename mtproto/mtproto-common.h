/* n此文件是MTProto-Server的一部分n n MTProto-Server是自由软件:您可以根据自由软件基金会发布的GNU通用公共许可证的条款重新发布和/或修改n它，可以是许可证的第2版，也可以是n(由您选择)任何更高版本。n n MTProto-Server发布是希望它有用，n但没有任何保证；甚至没有对适销性或特定用途适用性的暗示担保。更多细节请参见n GNU通用公共许可证。n n你应该已经收到了一份GNU通用公共许可证n和MTProto-Server。如果没有，请参阅<http://www.gnu.org/licenses/ >。n n这个程序是在GPL下发布的，但是允许编译、链接和/或使用OpenSSL。n您可以自由地从衍生作品中删除此项豁免。n n版权所有2012-2015 Nikolai Durov n 2012-2013 Andrey lopa tin n 2014-2018 Telegram Messenger Inc n */n # pragma once n # include < string . h > n # include < OpenSSL/RSA . h > n # include < OpenSSL/bn . h > n # include < OpenSSL/AES . h > n # include " RPC-const . h " n # define TLS _ push()t { struct TL _ tn # define TLS _ pop()TTL _ out _ state _ free(tlio _ out)；} n #定义TLS _ START(C)t ttls _ push()；tls_init_tcp_raw_msg (tlio_out，C，0)；n # define TLS _ START _ un align(C)ttls _ push()；TLS _ init _ TCP _ raw _ msg _ unaligned(tlio _ out，C，0)；n #定义TLS _ END t TTL _ store _ END _ ext(0)；TLS _ pop()；n n/* DH密钥交换协议数据结构*/n # define tCODE _ REQ _ pq t t0x 60469778n # define tCODE _ REQ _ pq _ multi t t 0x be 7 E8 ef 1n # define CODE _ REQ _ DH _ params t t 0x d 712 E4 be n # define CODE _ set _ client _ DH _ params t 0xf 5045 f 1n/* RPC for front/PROXY */n # define tRPC _ PROXY _ REQ t t 0x 36 cef 1 ee nn char msg _ key[16]；n //加密部分，以加密头n long long server_salt开头；n long长会话_ idn //第一条消息跟在n long long msg_id后面；int seq _ non int msg _ len//可被4 n整除int MESSAGE[MAX _ MESSAGE _ INTS+8]；n }；n n # define MAX _ PROXY _ EXTRA _ BYTES t 16384n n struct RPC _ PROXY _ req { n int type；t// RPC_PROXY_REQ n int标志；n long long ext _ conn _ idn未签名的char remote _ IPv6[16]；int远程端口；n未签名的char our _ IPv6[16]；在我们的港口；n union { n int data[0]；n struct { n int extra _ bytesn int EXTRA[MAX _ PROXY _ EXTRA _ BYTES/4]；n }；n }；n }；n构造rpc _ proxy _ ans { n int typet// RPC_PROXY_ANS n int标志；t// +16 =小错误包，+8 =立即刷新n long long ext _ conn _ idn int data[]；n }；n构造rpc _ close _ conn { n int typet//RPC _ CLOSE _ CONN n long long ext _ CONN _ id；n }；n struct RPC _ close _ ext { n int type；t//RPC _ CLOSE _ EXT n long long EXT _ conn _ id；n }；n构造rpc _ simple _ ack { n int typet//RPC _ SIMPLE _ ACK n long long ext _ conn _ id；n int confirm _ keyn }；n n #杂注包(pop)
#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
#	System Required: CentOS/Debian/Ubuntu
#	Description: MTProxy
#	Version: 1.0.8
#	Author: Toyo
#	Blog: https://doub.io/shell-jc7/
#=================================================

sh_ver="1.0.8"
filepath=$(cd "$(dirname "$0")"; pwd)
file_1=$(echo -e "${filepath}"|awk -F "$0" '{print $1}')
file="/usr/local/mtproxy"
mtproxy_file="/usr/local/mtproxy/mtproto-proxy"
mtproxy_conf="/usr/local/mtproxy/mtproxy.conf"
mtproxy_log="/usr/local/mtproxy/mtproxy.log"
mtproxy_secret="/usr/local/mtproxy/proxy-secret"
mtproxy_multi="/usr/local/mtproxy/proxy-multi.conf"
Crontab_file="/usr/bin/crontab"

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Green_font_prefix}[注意]${Font_color_suffix}"

check_root(){
	[[ $EUID != 0 ]] && echo -e "${Error} 当前非ROOT账号(或没有ROOT权限)，无法继续操作，请更换ROOT账号或使用 ${Green_background_prefix}sudo su${Font_color_suffix} 命令获取临时ROOT权限（执行后可能会提示输入当前账号的密码）。" && exit 1
}
#检查系统
check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
    fi
	#bit=`uname -m`
}
check_installed_status(){
	[[ ! -e ${mtproxy_file} ]] && echo -e "${Error} MTProxy 没有安装，请检查 !" && exit 1
}
check_crontab_installed_status(){
	if [[ ! -e ${Crontab_file} ]]; then
		echo -e "${Error} Crontab 没有安装，开始安装..."
		if [[ ${release} == "centos" ]]; then
			yum install crond -y
		else
			apt-get install cron -y
		fi
		if [[ ! -e ${Crontab_file} ]]; then
			echo -e "${Error} Crontab 安装失败，请检查！" && exit 1
		else
			echo -e "${Info} Crontab 安装成功！"
		fi
	fi
}
check_pid(){
	PID=`ps -ef| grep "./mtproto-proxy "| grep -v "grep" | grep -v "init.d" |grep -v "service" |awk '{print $2}'`
}
Download_mtproxy(){
	mkdir '/tmp/mtproxy'
	cd '/tmp/mtproxy'
	# wget -N --no-check-certificate "https://github.com/TelegramMessenger/MTProxy/archive/master.zip"
	git clone https://github.com/TelegramMessenger/MTProxy.git
	[[ ! -e "MTProxy/" ]] && echo -e "${Error} MTProxy 下载失败!" && cd '/tmp' && rm -rf '/tmp/mtproxy' && exit 1
	cd MTProxy
	make
	[[ ! -e "objs/bin/mtproto-proxy" ]] && echo -e "${Error} MTProxy 编译失败!" && echo -e "另外，如果在上面几行看到 ${Green_font_prefix}xxxxx option \"-std=gnu11\"${Font_color_suffix} 字样，说明是系统版本过低，请尝试更换系统重试！" && make clean && cd '/tmp' && rm -rf '/tmp/mtproxy' && exit 1
	[[ ! -e "${file}" ]] && mkdir "${file}"
	\cp -f objs/bin/mtproto-proxy "${file}"
	chmod +x "${mtproxy_file}"
	cd '/tmp'
	rm -rf '/tmp/mtproxy'
}
Download_secret(){
	[[ -e "${mtproxy_secret}" ]] && rm -rf "${mtproxy_secret}"
	wget --no-check-certificate -q "https://core.telegram.org/getProxySecret" -O "${mtproxy_secret}"
	[[ ! -e "${mtproxy_secret}" ]] && echo -e "${Error} MTProxy Secret下载失败! 脚本将会继续安装但会启动失败，请尝试手动下载：${Green_font_prefix}wget --no-check-certificate -q \"https://core.telegram.org/getProxySecret\" -O \"${mtproxy_secret}\"${Font_color_suffix}"
	echo -e "${Info} MTProxy Secret下载成功!"
}
Download_multi(){
	[[ -e "${mtproxy_multi}" ]] && rm -rf "${mtproxy_multi}"
	wget --no-check-certificate -q "https://core.telegram.org/getProxyConfig" -O "${mtproxy_multi}"
	[[ ! -e "${mtproxy_multi}" ]] && echo -e "${Error} MTProxy Multi下载失败!脚本将会继续安装但会启动失败，请尝试手动下载：${Green_font_prefix}wget --no-check-certificate -q \"https://core.telegram.org/getProxyConfig\" -O \"${mtproxy_multi}\"${Font_color_suffix}"
	echo -e "${Info} MTProxy Secret下载成功!"
}
Service_mtproxy(){
	if [[ ${release} = "centos" ]]; then
		if ! wget --no-check-certificate "https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/service/mtproxy_centos" -O /etc/init.d/mtproxy; then
			echo -e "${Error} MTProxy服务 管理脚本下载失败 !"
			rm -rf "${file}"
			exit 1
		fi
		chmod +x "/etc/init.d/mtproxy"
		chkconfig --add mtproxy
		chkconfig mtproxy on
	else
		if ! wget --no-check-certificate "https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/service/mtproxy_debian" -O /etc/init.d/mtproxy; then
			echo -e "${Error} MTProxy服务 管理脚本下载失败 !"
			rm -rf "${file}"
			exit 1
		fi
		chmod +x "/etc/init.d/mtproxy"
		update-rc.d -f mtproxy defaults
	fi
	echo -e "${Info} MTProxy服务 管理脚本下载完成 !"
}
Installation_dependency(){
	if [[ ${release} == "centos" ]]; then
		Centos_yum
	else
		Debian_apt
	fi
	\cp -f /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
}
Centos_yum(){
	cat /etc/redhat-release |grep 7\..*|grep -i centos>/dev/null
	yum update
	if [[ $? = 0 ]]; then
		yum install -y openssl-devel zlib-devel git
	else
		yum install -y openssl-devel zlib-devel git
	fi
	yum groupinstall "Development Tools" -y
}
Debian_apt(){
	cat /etc/issue |grep 9\..*>/dev/null
	apt-get update
	if [[ $? = 0 ]]; then
		apt-get install -y build-essential libssl-dev zlib1g-dev git
	else
		apt-get install -y build-essential libssl-dev zlib1g-dev git
	fi
}
Write_config(){
	cat > ${mtproxy_conf}<<-EOF
PORT = ${mtp_port}
PASSWORD = ${mtp_passwd}
TAG = ${mtp_tag}
NAT = ${mtp_nat}
EOF
}
Read_config(){
	[[ ! -e ${mtproxy_conf} ]] && echo -e "${Error} MTProxy 配置文件不存在 !" && exit 1
	port=$(cat ${mtproxy_conf}|grep 'PORT = '|awk -F 'PORT = ' '{print $NF}')
	passwd=$(cat ${mtproxy_conf}|grep 'PASSWORD = '|awk -F 'PASSWORD = ' '{print $NF}')
	tag=$(cat ${mtproxy_conf}|grep 'TAG = '|awk -F 'TAG = ' '{print $NF}')
	nat=$(cat ${mtproxy_conf}|grep 'NAT = '|awk -F 'NAT = ' '{print $NF}')
}
Set_port(){
	while true
		do
		echo -e "请输入 MTProxy 端口 [1-65535]"
		read -e -p "(默认: 443):" mtp_port
		[[ -z "${mtp_port}" ]] && mtp_port="443"
		echo $((${mtp_port}+0)) &>/dev/null
		if [[ $? -eq 0 ]]; then
			if [[ ${mtp_port} -ge 1 ]] && [[ ${mtp_port} -le 65535 ]]; then
				echo && echo "========================"
				echo -e "	端口 : ${Red_background_prefix} ${mtp_port} ${Font_color_suffix}"
				echo "========================" && echo
				break
			else
				echo "输入错误, 请输入正确的端口。"
			fi
		else
			echo "输入错误, 请输入正确的端口。"
		fi
		done
}
Set_passwd(){
	while true
		do
		echo "请输入 MTProxy 密匙（手动输入必须为32位，[0-9][a-z][A-Z]，建议随机生成）"
		read -e -p "(避免出错，强烈推荐随机生成，直接回车):" mtp_passwd
		if [[ -z "${mtp_passwd}" ]]; then
			mtp_passwd=$(date +%s%N | md5sum | head -c 32)
		else
			[[ ${#mtp_passwd} != 32 ]] && echo -e "${Error} 请输入正确的密匙（32位字符）。" && continue
		fi
		echo && echo "========================"
		echo -e "	密码 : ${Red_background_prefix} dd${mtp_passwd} ${Font_color_suffix}"
		echo "========================" && echo
		break
	done
}
Set_tag(){
	echo "请输入 MTProxy 的 TAG标签（TAG标签必须是32位，TAG标签只有在通过官方机器人 @MTProxybot 分享代理账号后才会获得，不清楚请留空回车）"
	read -e -p "(默认：回车跳过):" mtp_tag
	if [[ ! -z "${mtp_tag}" ]]; then
		echo && echo "========================"
		echo -e "	TAG : ${Red_background_prefix} ${mtp_tag} ${Font_color_suffix}"
		echo "========================" && echo
	fi
}
Set_nat(){
	echo -e "\n=== 当前服务器所有网卡信息：\n"
	if [[ -e "/sbin/ip" ]]; then
		ip addr show
	else
		ifconfig
	fi
	echo -e "\n== 解释：网卡名 lo 指的是本机，请无视。
== 解释：一般情况下，主网卡名为 eth0，Debian9系统为 ens3，CentOS Ubuntu最新系统可能为 enpXsX(X代表数字或字母)。OpenVZ 虚拟化为 venet0\n"
	echo -e "如果本机是NAT服务器（谷歌云、微软云、阿里云等，网卡绑定的IP为 10.xx.xx.xx 开头的），则请输入你的服务器内网IP，否则会导致无法使用。如果不是请直接回车！"
	read -e -p "(默认：回车跳过):" mtp_nat
	if [[ -z "${mtp_nat}" ]]; then
		mtp_nat=""
	else
		getip
		mtp_nat="${mtp_nat}:${ip}"
		echo && echo "========================"
		echo -e "	NAT : ${Red_background_prefix} ${mtp_nat} ${Font_color_suffix}"
		echo "========================" && echo
	fi
}
Set_mtproxy(){
	check_installed_status
	echo && echo -e "你要做什么？
 ${Green_font_prefix} 1.${Font_color_suffix}  修改 端口配置
 ${Green_font_prefix} 2.${Font_color_suffix}  修改 密码配置
 ${Green_font_prefix} 3.${Font_color_suffix}  修改 TAG 配置
 ${Green_font_prefix} 4.${Font_color_suffix}  修改 NAT 配置
 ${Green_font_prefix} 5.${Font_color_suffix}  修改 全部配置
————————————————
 ${Green_font_prefix} 6.${Font_color_suffix}  更新 Telegram IP段(无需频繁更新)
 ${Green_font_prefix} 7.${Font_color_suffix}  更新 Telegram 密匙(一般不用管)
————————————————
 ${Green_font_prefix} 8.${Font_color_suffix}  定时 更新 Telegram IP段
 ${Green_font_prefix} 9.${Font_color_suffix}  监控 运行状态
 ${Green_font_prefix}10.${Font_color_suffix}  监控 外网IP变更" && echo
	read -e -p "(默认: 取消):" mtp_modify
	[[ -z "${mtp_modify}" ]] && echo "已取消..." && exit 1
	if [[ "${mtp_modify}" == "1" ]]; then
		Read_config
		Set_port
		mtp_passwd=${passwd}
		mtp_tag=${tag}
		mtp_nat=${nat}
		Write_config
		Del_iptables
		Add_iptables
		Restart_mtproxy
	elif [[ "${mtp_modify}" == "2" ]]; then
		Read_config
		Set_passwd
		mtp_port=${port}
		mtp_tag=${tag}
		mtp_nat=${nat}
		Write_config
		Restart_mtproxy
	elif [[ "${mtp_modify}" == "3" ]]; then
		Read_config
		Set_tag
		mtp_port=${port}
		mtp_passwd=${passwd}
		mtp_nat=${nat}
		Write_config
		Restart_mtproxy
	elif [[ "${mtp_modify}" == "4" ]]; then
		Read_config
		Set_nat
		mtp_port=${port}
		mtp_passwd=${passwd}
		mtp_tag=${tag}
		Write_config
		Restart_mtproxy
	elif [[ "${mtp_modify}" == "5" ]]; then
		Read_config
		Set_port
		Set_passwd
		Set_tag
		Set_nat
		Write_config
		Restart_mtproxy
	elif [[ "${mtp_modify}" == "6" ]]; then
		Update_multi
	elif [[ "${mtp_modify}" == "7" ]]; then
		Update_secret
	elif [[ "${mtp_modify}" == "8" ]]; then
		Set_crontab_update_multi
	elif [[ "${mtp_modify}" == "9" ]]; then
		Set_crontab_monitor_mtproxy
	elif [[ "${mtp_modify}" == "10" ]]; then
		Set_crontab_monitorip
	else
		echo -e "${Error} 请输入正确的数字(1-10)" && exit 1
	fi
}
Install_mtproxy(){
	check_root
	[[ -e ${mtproxy_file} ]] && echo -e "${Error} 检测到 MTProxy 已安装 !" && exit 1
	echo -e "${Info} 开始设置 用户配置..."
	Set_port
	Set_passwd
	Set_tag
	Set_nat
	echo -e "${Info} 开始安装/配置 依赖..."
	Installation_dependency
	echo -e "${Info} 开始下载/安装..."
	Download_mtproxy
	Download_secret
	Download_multi
	echo -e "${Info} 开始下载/安装 服务脚本(init)..."
	Service_mtproxy
	echo -e "${Info} 开始写入 配置文件..."
	Write_config
	echo -e "${Info} 开始设置 iptables防火墙..."
	Set_iptables
	echo -e "${Info} 开始添加 iptables防火墙规则..."
	Add_iptables
	echo -e "${Info} 开始保存 iptables防火墙规则..."
	Save_iptables
	echo -e "${Info} 所有步骤 安装完毕，开始启动..."
	Start_mtproxy
}
Start_mtproxy(){
	check_installed_status
	check_pid
	[[ ! -z ${PID} ]] && echo -e "${Error} MTProxy 正在运行，请检查 !" && exit 1
	/etc/init.d/mtproxy start
	sleep 1s
	check_pid
	[[ ! -z ${PID} ]] && View_mtproxy
}
Stop_mtproxy(){
	check_installed_status
	check_pid
	[[ -z ${PID} ]] && echo -e "${Error} MTProxy 没有运行，请检查 !" && exit 1
	/etc/init.d/mtproxy stop
}
Restart_mtproxy(){
	check_installed_status
	check_pid
	[[ ! -z ${PID} ]] && /etc/init.d/mtproxy stop
	/etc/init.d/mtproxy start
	sleep 1s
	check_pid
	[[ ! -z ${PID} ]] && View_mtproxy
}
Update_mtproxy(){
	echo -e "${Tip} 因为官方无最新版本号，所以无法对比版本，请自行判断是否需要更新。是否更新？[Y/n]"
	read -e -p "(默认: y):" yn
	[[ -z "${yn}" ]] && yn="y"
	if [[ ${yn} == [Yy] ]]; then
		check_installed_status
		check_pid
		[[ ! -z $PID ]] && /etc/init.d/mtproxy stop
		rm -rf ${mtproxy_file}
		Download_mtproxy
		echo -e "${Info} MTProxy 更新完成..."
		Start_mtproxy
	fi
	
}
Uninstall_mtproxy(){
	check_installed_status
	echo "确定要卸载 MTProxy ? (y/N)"
	echo
	read -e -p "(默认: n):" unyn
	[[ -z ${unyn} ]] && unyn="n"
	if [[ ${unyn} == [Yy] ]]; then
		check_pid
		[[ ! -z $PID ]] && kill -9 ${PID}
		if [[ -e ${mtproxy_conf} ]]; then
			port=$(cat ${mtproxy_conf}|grep 'PORT = '|awk -F 'PORT = ' '{print $NF}')
			Del_iptables
			Save_iptables
		fi
		if [[ ! -z $(crontab -l | grep "mtproxy.sh monitor") ]]; then
			crontab_monitor_mtproxy_cron_stop
		fi
		if [[ ! -z $(crontab -l | grep "mtproxy.sh update") ]]; then
			crontab_update_mtproxy_cron_stop
		fi
		rm -rf "${file}"
		if [[ ${release} = "centos" ]]; then
			chkconfig --del mtproxy
		else
			update-rc.d -f mtproxy remove
		fi
		rm -rf "/etc/init.d/mtproxy"
		echo && echo "MTProxy 卸载完成 !" && echo
	else
		echo && echo "卸载已取消..." && echo
	fi
}
getip(){
	ip=$(wget -qO- -t1 -T2 ipinfo.io/ip)
	if [[ -z "${ip}" ]]; then
		ip=$(wget -qO- -t1 -T2 api.ip.sb/ip)
		if [[ -z "${ip}" ]]; then
			ip=$(wget -qO- -t1 -T2 members.3322.org/dyndns/getip)
			if [[ -z "${ip}" ]]; then
				ip="VPS_IP"
			fi
		fi
	fi
}
View_mtproxy(){
	check_installed_status
	Read_config
	getip
	clear && echo
	echo -e "Mtproto Proxy 用户配置："
	echo -e "————————————————"
	echo -e " 地址\t: ${Green_font_prefix}${ip}${Font_color_suffix}"
	echo -e " 端口\t: ${Green_font_prefix}${port}${Font_color_suffix}"
	echo -e " 密匙\t: ${Green_font_prefix}dd${passwd}${Font_color_suffix}"
	[[ ! -z "${nat}" ]] && echo -e " NAT \t: ${Green_font_prefix}${nat}${Font_color_suffix}"
	[[ ! -z "${tag}" ]] && echo -e " TAG \t: ${Green_font_prefix}${tag}${Font_color_suffix}"
	echo -e " 链接\t: ${Red_font_prefix}tg://proxy?server=${ip}&port=${port}&secret=dd${passwd}${Font_color_suffix}"
	echo -e " 链接\t: ${Red_font_prefix}https://t.me/proxy?server=${ip}&port=${port}&secret=dd${passwd}${Font_color_suffix}"
	echo
	echo -e " ${Red_font_prefix}注意\t:${Font_color_suffix} 密匙头部的 ${Green_font_prefix}dd${Font_color_suffix} 字符是代表客户端启用${Green_font_prefix}随机填充混淆模式${Font_color_suffix}，如果不需要请手动删除。\n     \t  另外，在官方机器人处分享账号获取TAG标签时记得删除，获取TAG标签后分享时可以再加上。"
}
View_Log(){
	check_installed_status
	[[ ! -e ${mtproxy_log} ]] && echo -e "${Error} MTProxy 日志文件不存在 !" && exit 1
	echo && echo -e "${Tip} 按 ${Red_font_prefix}Ctrl+C${Font_color_suffix} 终止查看日志" && echo -e "如果需要查看完整日志内容，请用 ${Red_font_prefix}cat ${mtproxy_log}${Font_color_suffix} 命令。" && echo
	tail -f ${mtproxy_log}
}
Update_secret(){
	rm -rf "${mtproxy_secret}"
	Download_secret
	Restart_mtproxy
}
Update_multi(){
	rm -rf "${mtproxy_multi}"
	Download_multi
	Restart_mtproxy
}
# 显示 连接信息
debian_View_user_connection_info(){
	format_1=$1
	Read_config
	user_IP=`netstat -anp |grep 'ESTABLISHED' |grep 'mtproto' |grep 'tcp' |grep ":${port} " |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`
	if [[ -z ${user_IP} ]]; then
		user_IP_total="0"
		echo -e "端口: ${Green_font_prefix}"${port}"${Font_color_suffix}\t 链接IP总数: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t 当前链接IP: "
	else
		user_IP_total=`echo -e "${user_IP}"|wc -l`
		if [[ ${format_1} == "IP_address" ]]; then
			echo -e "端口: ${Green_font_prefix}"${port}"${Font_color_suffix}\t 链接IP总数: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t 当前链接IP: "
			get_IP_address
			echo
		else
			user_IP=$(echo -e "\n${user_IP}")
			echo -e "端口: ${Green_font_prefix}"${user_port}"${Font_color_suffix}\t 链接IP总数: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t 当前链接IP: ${Green_font_prefix}${user_IP}${Font_color_suffix}\n"
		fi
	fi
	user_IP=""
}
centos_View_user_connection_info(){
	format_1=$1
	Read_config
	user_IP=`netstat -anp |grep 'ESTABLISHED' |grep 'mtproto' |grep 'tcp' |grep ":${port} "|awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`
	if [[ -z ${user_IP} ]]; then
		user_IP_total="0"
		echo -e "端口: ${Green_font_prefix}"${port}"${Font_color_suffix}\t 链接IP总数: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t 当前链接IP: "
	else
		user_IP_total=`echo -e "${user_IP}"|wc -l`
		if [[ ${format_1} == "IP_address" ]]; then
			echo -e "端口: ${Green_font_prefix}"${port}"${Font_color_suffix}\t 链接IP总数: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t 当前链接IP: "
			get_IP_address
			echo
		else
			user_IP=$(echo -e "\n${user_IP}")
			echo -e "端口: ${Green_font_prefix}"${port}"${Font_color_suffix}\t 链接IP总数: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t 当前链接IP: ${Green_font_prefix}${user_IP}${Font_color_suffix}\n"
		fi
	fi
	user_IP=""
}
View_user_connection_info(){
	check_installed_status
	echo && echo -e "请选择要显示的格式：
 ${Green_font_prefix}1.${Font_color_suffix} 显示 IP 格式
 ${Green_font_prefix}2.${Font_color_suffix} 显示 IP+IP归属地 格式" && echo
	read -e -p "(默认: 1):" mtproxy_connection_info
	[[ -z "${mtproxy_connection_info}" ]] && mtproxy_connection_info="1"
	if [[ "${mtproxy_connection_info}" == "1" ]]; then
		View_user_connection_info_1 ""
	elif [[ "${mtproxy_connection_info}" == "2" ]]; then
		echo -e "${Tip} 检测IP归属地(ipip.net)，如果IP较多，可能时间会比较长..."
		View_user_connection_info_1 "IP_address"
	else
		echo -e "${Error} 请输入正确的数字(1-2)" && exit 1
	fi
}
View_user_connection_info_1(){
	format=$1
	if [[ ${release} = "centos" ]]; then
		cat /etc/redhat-release |grep 7\..*|grep -i centos>/dev/null
		if [[ $? = 0 ]]; then
			debian_View_user_connection_info "$format"
		else
			centos_View_user_connection_info "$format"
		fi
	else
		debian_View_user_connection_info "$format"
	fi
}
get_IP_address(){
	if [[ ! -z ${user_IP} ]]; then
		for((integer_1 = ${user_IP_total}; integer_1 >= 1; integer_1--))
		do
			IP=$(echo "${user_IP}" |sed -n "$integer_1"p)
			IP_address=$(wget -qO- -t1 -T2 http://freeapi.ipip.net/${IP}|sed 's/\"//g;s/,//g;s/\[//g;s/\]//g')
			echo -e "${Green_font_prefix}${IP}${Font_color_suffix} (${IP_address})"
			sleep 1s
		done
	fi
}
Set_crontab_monitor_mtproxy(){
	check_crontab_installed_status
	crontab_monitor_mtproxy_status=$(crontab -l|grep "mtproxy.sh monitor")
	if [[ -z "${crontab_monitor_mtproxy_status}" ]]; then
		echo && echo -e "当前监控运行状态模式: ${Red_font_prefix}未开启${Font_color_suffix}" && echo
		echo -e "确定要开启 ${Green_font_prefix}MTProxy 服务端运行状态监控${Font_color_suffix} 功能吗？(当进程关闭则自动启动 MTProxy 服务端)[Y/n]"
		read -e -p "(默认: y):" crontab_monitor_mtproxy_status_ny
		[[ -z "${crontab_monitor_mtproxy_status_ny}" ]] && crontab_monitor_mtproxy_status_ny="y"
		if [[ ${crontab_monitor_mtproxy_status_ny} == [Yy] ]]; then
			crontab_monitor_mtproxy_cron_start
		else
			echo && echo "	已取消..." && echo
		fi
	else
		echo && echo -e "当前监控运行状态模式: ${Green_font_prefix}已开启${Font_color_suffix}" && echo
		echo -e "确定要关闭 ${Red_font_prefix}MTProxy 服务端运行状态监控${Font_color_suffix} 功能吗？(当进程关闭则自动启动 MTProxy 服务端)[y/N]"
		read -e -p "(默认: n):" crontab_monitor_mtproxy_status_ny
		[[ -z "${crontab_monitor_mtproxy_status_ny}" ]] && crontab_monitor_mtproxy_status_ny="n"
		if [[ ${crontab_monitor_mtproxy_status_ny} == [Yy] ]]; then
			crontab_monitor_mtproxy_cron_stop
		else
			echo && echo "	已取消..." && echo
		fi
	fi
}
crontab_monitor_mtproxy_cron_start(){
	crontab -l > "$file_1/crontab.bak"
	sed -i "/mtproxy.sh monitor/d" "$file_1/crontab.bak"
	echo -e "\n* * * * * /bin/bash $file_1/mtproxy.sh monitor" >> "$file_1/crontab.bak"
	crontab "$file_1/crontab.bak"
	rm -r "$file_1/crontab.bak"
	cron_config=$(crontab -l | grep "mtproxy.sh monitor")
	if [[ -z ${cron_config} ]]; then
		echo -e "${Error} MTProxy 服务端运行状态监控功能 启动失败 !" && exit 1
	else
		echo -e "${Info} MTProxy 服务端运行状态监控功能 启动成功 !"
	fi
}
crontab_monitor_mtproxy_cron_stop(){
	crontab -l > "$file_1/crontab.bak"
	sed -i "/mtproxy.sh monitor/d" "$file_1/crontab.bak"
	crontab "$file_1/crontab.bak"
	rm -r "$file_1/crontab.bak"
	cron_config=$(crontab -l | grep "mtproxy.sh monitor")
	if [[ ! -z ${cron_config} ]]; then
		echo -e "${Error} MTProxy 服务端运行状态监控功能 停止失败 !" && exit 1
	else
		echo -e "${Info} MTProxy 服务端运行状态监控功能 停止成功 !"
	fi
}
crontab_monitor_mtproxy(){
	check_installed_status
	check_pid
	#echo "${PID}"
	if [[ -z ${PID} ]]; then
		echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] 检测到 MTProxy服务端 未运行 , 开始启动..." | tee -a ${mtproxy_log}
		/etc/init.d/mtproxy start
		sleep 1s
		check_pid
		if [[ -z ${PID} ]]; then
			echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] MTProxy服务端 启动失败..." | tee -a ${mtproxy_log}
		else
			echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] MTProxy服务端 启动成功..." | tee -a ${mtproxy_log}
		fi
	else
		echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] MTProxy服务端 进程运行正常..." | tee -a ${mtproxy_log}
	fi
}
Set_crontab_update_multi(){
	check_crontab_installed_status
	crontab_update_mtproxy_status=$(crontab -l|grep "mtproxy.sh update")
	if [[ -z "${crontab_update_mtproxy_status}" ]]; then
		echo && echo -e "当前自动更新 Telegram IP段功能: ${Red_font_prefix}未开启${Font_color_suffix}" && echo
		echo -e "确定要开启 ${Green_font_prefix}MTProxy 自动更新 Telegram IP段${Font_color_suffix} 功能吗？[Y/n]"
		read -e -p "(默认: y):" crontab_update_mtproxy_status_ny
		[[ -z "${crontab_update_mtproxy_status_ny}" ]] && crontab_update_mtproxy_status_ny="y"
		if [[ ${crontab_update_mtproxy_status_ny} == [Yy] ]]; then
			crontab_update_mtproxy_cron_start
		else
			echo && echo "	已取消..." && echo
		fi
	else
		echo && echo -e "当前自动更新 Telegram IP段功能: ${Green_font_prefix}已开启${Font_color_suffix}" && echo
		echo -e "确定要关闭 ${Red_font_prefix}MTProxy 自动更新 Telegram IP段${Font_color_suffix} 功能吗？[y/N]"
		read -e -p "(默认: n):" crontab_update_mtproxy_status_ny
		[[ -z "${crontab_update_mtproxy_status_ny}" ]] && crontab_update_mtproxy_status_ny="n"
		if [[ ${crontab_update_mtproxy_status_ny} == [Yy] ]]; then
			crontab_update_mtproxy_cron_stop
		else
			echo && echo "	已取消..." && echo
		fi
	fi
}
crontab_update_mtproxy_cron_start(){
	crontab -l > "$file_1/crontab.bak"
	sed -i "/mtproxy.sh update/d" "$file_1/crontab.bak"
	echo -e "\n10 3 * * * /bin/bash $file_1/mtproxy.sh update" >> "$file_1/crontab.bak"
	crontab "$file_1/crontab.bak"
	rm -r "$file_1/crontab.bak"
	cron_config=$(crontab -l | grep "mtproxy.sh update")
	if [[ -z ${cron_config} ]]; then
		echo -e "${Error} MTProxy 自动更新 Telegram IP段功能 启动失败 !" && exit 1
	else
		echo -e "${Info} MTProxy 自动更新 Telegram IP段功能 启动成功 !"
	fi
}
crontab_update_mtproxy_cron_stop(){
	crontab -l > "$file_1/crontab.bak"
	sed -i "/mtproxy.sh update/d" "$file_1/crontab.bak"
	crontab "$file_1/crontab.bak"
	rm -r "$file_1/crontab.bak"
	cron_config=$(crontab -l | grep "mtproxy.sh update")
	if [[ ! -z ${cron_config} ]]; then
		echo -e "${Error} MTProxy 自动更新 Telegram IP段功能 停止失败 !" && exit 1
	else
		echo -e "${Info} MTProxy 自动更新 Telegram IP段功能 停止成功 !"
	fi
}
crontab_update_mtproxy(){
	check_installed_status
	check_pid
	rm -rf "${mtproxy_multi}"
	Download_multi
	echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Telegram IP段自动更新完成..." | tee -a ${mtproxy_log}
	/etc/init.d/mtproxy restart
}
Set_crontab_monitorip(){
	check_crontab_installed_status
	crontab_monitor_status=$(crontab -l|grep "mtproxy.sh monitorip")
	if [[ -z "${crontab_monitor_status}" ]]; then
		echo && echo -e "当前监控外网IP模式: ${Red_font_prefix}未开启${Font_color_suffix}" && echo
		echo -e "确定要开启 ${Green_font_prefix}服务器外网IP变更监控${Font_color_suffix} 功能吗？(当服务器外网IP变化后，自动重新配置并重启服务端)[Y/n]"
		read -e -p "(默认: y):" crontab_monitor_status_ny
		[[ -z "${crontab_monitor_status_ny}" ]] && crontab_monitor_status_ny="y"
		if [[ ${crontab_monitor_status_ny} == [Yy] ]]; then
			crontab_monitor_cron_start2
		else
			echo && echo "	已取消..." && echo
		fi
	else
		echo && echo -e "当前监控外网IP模式: ${Green_font_prefix}已开启${Font_color_suffix}" && echo
		echo -e "确定要关闭 ${Red_font_prefix}服务器外网IP变更监控${Font_color_suffix} 功能吗？(当服务器外网IP变化后，自动重新配置并重启服务端)[Y/n]"
		read -e -p "(默认: n):" crontab_monitor_status_ny
		[[ -z "${crontab_monitor_status_ny}" ]] && crontab_monitor_status_ny="n"
		if [[ ${crontab_monitor_status_ny} == [Yy] ]]; then
			crontab_monitor_cron_stop2
		else
			echo && echo "	已取消..." && echo
		fi
	fi
}
crontab_monitor_cron_start2(){
	crontab -l > "$file_1/crontab.bak"
	sed -i "/mtproxy.sh monitorip/d" "$file_1/crontab.bak"
	echo -e "\n* * * * * /bin/bash $file_1/mtproxy.sh monitorip" >> "$file_1/crontab.bak"
	crontab "$file_1/crontab.bak"
	rm -r "$file_1/crontab.bak"
	cron_config=$(crontab -l | grep "mtproxy.sh monitorip")
	if [[ -z ${cron_config} ]]; then
		echo -e "${Error} 服务器外网IP变更监控功能 启动失败 !" && exit 1
	else
		echo -e "${Info} 服务器外网IP变更监控功能 启动成功 !"
	fi
}
crontab_monitor_cron_stop2(){
	crontab -l > "$file_1/crontab.bak"
	sed -i "/mtproxy.sh monitorip/d" "$file_1/crontab.bak"
	crontab "$file_1/crontab.bak"
	rm -r "$file_1/crontab.bak"
	cron_config=$(crontab -l | grep "mtproxy.sh monitorip")
	if [[ ! -z ${cron_config} ]]; then
		echo -e "${Error} 服务器外网IP变更监控功能 停止失败 !" && exit 1
	else
		echo -e "${Info} 服务器外网IP变更监控功能 停止成功 !"
	fi
}
crontab_monitorip(){
	check_installed_status
	Read_config
	getip
	ipv4=$(echo "${nat}"|awk -F ':' '{print $2}')
	nat_ipv4=$(echo "${nat}"|awk -F ':' '{print $1}')
	if [[ "${ip}" != "VPS_IP" ]]; then
		if [[ "${ip}" != "${ipv4}" ]]; then
			echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] 检测到 服务器外网IP变更[旧: ${ipv4}，新: ${ip}], 开始重新配置并准备重启服务端..." | tee -a ${mtproxy_log}
			mtp_nat="${nat_ipv4}:${ip}"
			mtp_port=${port}
			mtp_passwd=${passwd}
			mtp_tag=${tag}
			Write_config
			Restart_mtproxy
		fi
	else
		echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] 服务器外网IPv4获取失败..." | tee -a ${mtproxy_log}
	fi
}
Add_iptables(){
	iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${mtp_port} -j ACCEPT
	#iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${mtp_port} -j ACCEPT
}
Del_iptables(){
	iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
	#iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
}
Save_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
	else
		iptables-save > /etc/iptables.up.rules
	fi
}
Set_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
		chkconfig --level 2345 iptables on
	else
		iptables-save > /etc/iptables.up.rules
		echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules' > /etc/network/if-pre-up.d/iptables
		chmod +x /etc/network/if-pre-up.d/iptables
	fi
}
Update_Shell(){
	sh_new_ver=$(wget --no-check-certificate -qO- -t1 -T3 "https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/mtproxy.sh"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1) && sh_new_type="github"
	[[ -z ${sh_new_ver} ]] && echo -e "${Error} 无法链接到 Github !" && exit 0
	if [[ -e "/etc/init.d/mtproxy" ]]; then
		rm -rf /etc/init.d/mtproxy
		Service_mtproxy
	fi
	wget -N --no-check-certificate "https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/mtproxy.sh" && chmod +x mtproxy.sh
	echo -e "脚本已更新为最新版本[ ${sh_new_ver} ] !(注意：因为更新方式为直接覆盖当前运行的脚本，所以可能下面会提示一些报错，无视即可)" && exit 0
}
check_sys
action=$1
if [[ "${action}" == "monitor" ]]; then
	crontab_monitor_mtproxy
elif [[ "${action}" == "update" ]]; then
	crontab_update_mtproxy
elif [[ "${action}" == "monitorip" ]]; then
	crontab_monitorip
else
	echo && echo -e "  MTProxy 一键管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
  ---- Toyo | doub.io/shell-jc7 ----
  
 ${Green_font_prefix} 0.${Font_color_suffix} 升级脚本
————————————
 ${Green_font_prefix} 1.${Font_color_suffix} 安装 MTProxy
 ${Green_font_prefix} 2.${Font_color_suffix} 更新 MTProxy
 ${Green_font_prefix} 3.${Font_color_suffix} 卸载 MTProxy
————————————
 ${Green_font_prefix} 4.${Font_color_suffix} 启动 MTProxy
 ${Green_font_prefix} 5.${Font_color_suffix} 停止 MTProxy
 ${Green_font_prefix} 6.${Font_color_suffix} 重启 MTProxy
————————————
 ${Green_font_prefix} 7.${Font_color_suffix} 设置 账号配置
 ${Green_font_prefix} 8.${Font_color_suffix} 查看 账号信息
 ${Green_font_prefix} 9.${Font_color_suffix} 查看 日志信息
 ${Green_font_prefix}10.${Font_color_suffix} 查看 链接信息
————————————" && echo
	if [[ -e ${mtproxy_file} ]]; then
		check_pid
		if [[ ! -z "${PID}" ]]; then
			echo -e " 当前状态: ${Green_font_prefix}已安装${Font_color_suffix} 并 ${Green_font_prefix}已启动${Font_color_suffix}"
		else
			echo -e " 当前状态: ${Green_font_prefix}已安装${Font_color_suffix} 但 ${Red_font_prefix}未启动${Font_color_suffix}"
		fi
	else
		echo -e " 当前状态: ${Red_font_prefix}未安装${Font_color_suffix}"
	fi
	echo
	read -e -p " 请输入数字 [0-10]:" num
	case "$num" in
		0)
		Update_Shell
		;;
		1)
		Install_mtproxy
		;;
		2)
		Update_mtproxy
		;;
		3)
		Uninstall_mtproxy
		;;
		4)
		Start_mtproxy
		;;
		5)
		Stop_mtproxy
		;;
		6)
		Restart_mtproxy
		;;
		7)
		Set_mtproxy
		;;
		8)
		View_mtproxy
		;;
		9)
		View_Log
		;;
		10)
		View_user_connection_info
		;;
		*)
		echo "请输入正确数字 [0-10]"
		;;
	esac
fi
