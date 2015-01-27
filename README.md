#dnsReflector
    dns调度器，用来将特定域名调度到指定服务器地址。
##一、编译：
    进入src/cache_engine目录，执行make操作。
##二、运行参数：
    -h              [Print help]
    -v              [Print version]
    -x              [set debug mode]
    -i ethx         [set input device name]
    -o ethy         [set output device name]
    -m              [set output next-hop mac addr eg:E41F134E7B42]
    
    示例：./dnsReflector -i INPUT_DEV -o OUTPUT_DEV -m MAC_ADDR
    
    Four config files : 
    dnsReflector config file : /usr/local/dnsReflector/etc/dnsReflector.conf 
    dns list file : /usr/local/dnsReflector/etc/dns.list 
    black ip addr list file : /usr/local/dnsReflector/etc/ip_black.list 
    white ip addr list file : /usr/local/dnsReflector/etc/ip_white.list 
##三、配置文件说明：
    1. dnsReflector.conf用来配置抓包时的过滤规则。
    
    2. dns.list文件请严格按照以下格式写入(且每行的行首和行尾必须不留空格):
       行首开始写域名,中间一个空格，之后是以;分隔的IP。
    
    示例：
    abc1.com 1.1.1.1;2.2.2.2;3.3.3.3;
    abc2.com 1.1.1.1;2.2.2.2;3.3.3.3;
    abc3.com 1.1.1.1;2.2.2.2;3.3.3.3;
    
    3. ip_black.list和ip_white.list文件中每行写一个IP或IP地址段。
      如果IP地址未写掩码，则默认掩码为32；如果要匹配全部的IP地址段，则将掩码写成0。
      如果行首以#开头，则该行被注释。
      如果不存在ip_white.list文件或者ip_white.list文件内容为空，则白名单匹配所有IP。
      如果不存在ip_black.list文件或者ip_black.list文件内容为空，则黑名单不匹配任何IP。
      被干扰的IP首先应该存在于ip_white.list文件中，且不存在于ip_black.list中。
    
    示例：
    192.168.30.24
    192.168.30.44/32
    192.168.20.0/24
    #192.168.1.1
    0.0.0.0/0
