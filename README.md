FGFW-Lite
=========
一个辅助突破网络审查的HTTP代理服务器。它能自动检查网站是否被墙，使用二级代理。

不用PAC，无需各种浏览器插件，用最简单的设置享受自由的网络。

##功能

- 符合HTTP1.1标准的HTTP代理服务器
- 自动设置系统代理(仅限Windows)
- 支持需要设置代理的局域网环境
- 地址栏搜索
- 自动升级到最新的稳定版本
- 使用多种方法检测网站是否被墙，并转发到二级代理
  - autoproxy-gfwlist
  - 自定义规则
  - 连接超时
  - 读操作超时
  - 连接被重置
- 自动避免使用HTTPS假证书
- 多种自定义规则
- ~~默认设置即可无障碍访问部分Google服务(GoAgent FORWARD)~~
- 支持FTP(仅限直接连接)
- 支持的二级代理
  - HTTP代理
  - HTTPS代理
  - Socks5代理
  - GoAgent
  - Shadowsocks
  - Snova(不支持GAE模式)

##快速开始

FGFW-Lite是便携软件，[下载](https://github.com/v3aqb/fgfw-lite/archive/master.zip)，解压即用。注意，**路径只支持英文，不能有空格**。

修改配置文件userconf.ini（参考userconf.sample.ini），可设置自己的goagent appid和其他二级代理。

设置浏览器代理服务器为：127.0.0.1:8118（当代理服务器设为127.0.0.1:8119时，所有出国流量走代理）

windows系统：运行FGFW_Lite.exe

Linux系统：运行fgfwlite-gtk.pyw

requirements under openSUSE:

    zypper install python-pyOpenSSL python-M2Crypto python-pycrypto python-Markdown python-repoze.lru python-ipaddr
    zypper install python-gevent  # for better performance
    zypper install python-vte  # gui

##自定义规则(./fgfw-lite/local.txt)

FGFW-Lite兼容[autoproxy规则](https://autoproxy.org/zh-CN/Rules)，不同之处：

对特定网址不使用规则。用于阻止对国内的网站误用代理，以及gfwlist中可直连的网站。

    @@||example.com

forcehttps

    |http://zh.wikipedia.com/search forcehttps

重定向

    http://www.baidu.com http://www.google.com

重定向(正则表达式)

    /^http://www.baidu.com/.*wd=([^&]*).*$/ /https://www.google.com/search?q=\1&ie=gb2312/

阻止访问特定网站

    ||dongtaiwang.com 403

为特定网站指定二级代理

    ||bbc.co.uk shadowsocks-uk
    ||weibo.com direct

##其他相关

cow https://github.com/cyfdecyf/cow

goagent https://code.google.com/p/goagent/

shadowsocks https://github.com/clowwindy/shadowsocks

snova https://code.google.com/p/snova/

pybuild https://github.com/goagent/pybuild
