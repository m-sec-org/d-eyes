# D-Eyes
D-Eyes为绿盟科技一款检测与响应工具，可在如下方面开展支撑：  
1. [x] 作为应急响应工具，支持勒索挖矿病毒及webshell等恶意样本排查检测，辅助安全工程师应急响应时排查入侵痕迹，定位恶意样本。  
2. [ ] 作为基线检查工具，辅助检测和排查操作系统配置缺陷；(TODO)  
3. [ ] 作为软件供应链安全检查工具，可提取web应用程序开源组件清单（sbom），判别引入的组件风险。(TODO)  

## 使用说明
###	运行
#### Windows
请以管理员身份运行cmd，之后再输入D-Eyes路径运行即可或进入终端后切换到D-Eyes程序目录下运行程序。
#### Linux
请以root身份运行。
###	文件扫描
> 若扫到恶意文件，会在D-Eyes所在目录下自动生成扫描结果D-Eyes.xlsx文件，若未检测到恶意文件则不会生成文件，会在终端进行提示。
#### Windows
1. 默认扫描(默认以5个线程扫描C盘)  
命令：`D-Eyes fs`
2. 指定路径扫描(-P 参数)  
单一路径扫描：`D-Eyes fs -P D:\tmp`
多个路径扫描：`D-Eyes fs -P C:\Windows\TEMP,D:\tmp,D:\tools`
3. 指定线程扫描(-t 参数)  
命令：`D-Eyes fs -P C:\Windows\TEMP,D:\tmp -t 3`
4. 指定单一规则扫描(-r 参数)  
命令：`D-Eyes fs -P D:\tmp -t 3 -r Ransom.Wannacrypt`
   > 规则名称即将yaraRules目录下的规则去掉后缀`.yar`, 如：指定`Ransom.Wannacrypt.yar`规则，即`-r Ransom.Wannacrypt`。
#### Linux
1. 默认扫描(默认以5个线程扫描全盘)  
命令：`./D-Eyes fs`
2. 指定路径扫描(-P 参数)  
单一路径扫描：`./D-Eyes fs -P /tmp`
多个路径扫描：`./D-Eyes fs -P /tmp,/var`
3.  指定线程扫描(-t 参数)  
命令：`./D-Eyes fs -P /tmp,/var -t 3`
4.  指定单一规则扫描(-r 参数)  
命令：`./D-Eyes fs -P /tmp -t 3 -r Ransom.Wannacrypt`
    > 规则名称即将yaraRules目录下的规则去掉后缀`.yar`, 如：指定`Ransom.Wannacrypt.yar`规则，即`-r Ransom.Wannacrypt`。



### 进程扫描
> 进程扫描的结果在终端上进行提示。
#### Windows:
1. 默认扫描(默认扫描全部进程)  
命令：`D-Eyes ps`
2. 指定进程pid扫描(-p参数)  
命令：`D-Eyes ps -p 1234`
3. 指定规则扫描(-r参数)  
命令：`D-Eyes ps -p 1234 -r Ransom.Wannacrypt`
4. 检测指定外联IP的进程  
可将恶意ip添加到工具目录`ip.config`文件当中，执行`D-Eyes ps`程序会自动检测是否有进程连接该IP，最后结果会输出到终端。  
`ip.config`文件格式(换行添加即可)，如：
    ```
    0.0.0.0
    127.0.0.1
    ```

#### Linux:
1. 默认扫描(默认扫描全部进程)  
命令：`./D-Eyes ps`
2. 指定进程pid扫描(-p参数)  
命令：`./D-Eyes ps -p 1234`
3. 指定规则扫描(-r参数)  
命令：`./D-Eyes ps -p 1234 -r Ransom.Wannacrypt`
4. 检测指定外联IP的进程  
可将恶意ip添加到工具目录`ip.config`文件当中，执行`D-Eyes ps`程序会自动检测是否有进程连接该IP，最后结果会输出到终端。  
`ip.config`文件格式(换行添加即可)，如：
    ```
    0.0.0.0
    127.0.0.1
    ```

### 查看主机信息
Windows命令：`D-Eyes host`  
Linux命令：  `./D-Eyes host`
### 查看主机网络信息，并导出外联IP
Windows命令：`D-Eyes netstat`    
Linux命令：  `./D-Eyes netstat`
> 主机若存在远程连接，执行该条命令后会在工具同级目录下自动生成“RemoteConnectionIP.csv”文件，之后可直接将该文件上传到“绿盟NTI威胁研判模块”查询主机所有远程连接IP信息。
绿盟NTI威胁研判模块网址：https://ti.nsfocus.com/advance/#/judge
### 查看主机账户
Windows命令：`D-Eyes users`  
Linux命令：   `./D-Eyes users`

### 显示主机CPU使用率前15个进程信息
Windows命令：`D-Eyes top`  
Linux命令：   `./D-Eyes top`
### 查看计划任务
Windows命令：`D-Eyes task`  
Linux命令：   `./D-Eyes task`
### 查看自启项
Windows命令：`D-Eyes autoruns`  
Linux命令：   `./D-Eyes autoruns`
### 导出主机基本信息
Windows命令：`D-Eyes summary`  
Linux命令：   `./D-Eyes summary`
> 执行该条命令后会在工具同级目录下自动生成“SummaryBaseInfo.txt”文件，文件内容包括主机系统信息、主机用户列表、主机计划任务及主机IP信息。
### Linux主机自检命令
Linux命令：   `./D-Eyes sc`
> 目前Linux自检功能支持以下模块检测：
空密码账户检测、SSH Server wrapper检测、SSH用户免密证书登录检测、主机 Sudoer检测、alias检测、Setuid检测、SSH登录爆破检测、主机Rootkit检测、主机历史命令检测、主机最近成功登录信息显示、主机计划任务内容检测、环境变量检测、系统启动服务检测、TCP Wrappers 检测、inetd配置文件检测、xinetd配置文件检测、预加载配置文件检测。
---
## ⚠️注意事项
在D-Eyes工具目录下子目录yaraRules中，部分规则会触发杀毒软件告警，因为该目录存放的规则文件与杀软查杀规则相符，会触发杀软告警，直接加白即可，不会存在实际危害。

## 附录：目前支持的检测规则
目前支持的恶意样本检测种类如下：
### 勒索：
Babuk、BadEncript、BadRabbit、BCrypt、BlackMatter、Cerber、Chaos、ChupaCabra、Common、Conti、Cryakl、CryptoLocker、cryt0y、DarkSide、Fonix、GandCrab、Globeimposter、Henry217、HiddenTear、LockBit、Locky、Magniber、Makop、MBRLocker、MedusaLocker、Nemty、NoCry、Petya、Phobos、Povlsomware、QNAPCrypt、Sarbloh、Satana、ScreenLocker、Sodinokibi、Stop、Termite、TeslaCrypt、Thanos、Tohnichi、TrumpLocker、Venus、VoidCrypt、Wannacrypt、WannaDie、WannaRen、Zeppelin
### 挖矿：
Wannamine、ELFcoinminer、givemexyz家族、Monero、TrojanCoinMiner
### 僵尸网络：
BlackMoon、Festi、Gafgyt、Kelihos、Mykings
### Webshell：
支持中国菜刀、Cknife、Weevely、蚁剑 antSword、冰蝎 Behinder、哥斯拉 Godzilla等常见工具的webshell脚本的检测。
