safeline_exp.py是雷池系统自动发现程序
360skyeye_exp.py是360天眼流量传感器程序

使用需知：
1、以上两个程序均已过滤掉源地址为172.16-172.31的私有地址

2、以上两个程序均已过滤掉请求地址为/%3Cdiv%20class=%22pagenav%22%3E%0A%09%3Cform%20name=%22fsmformvalue%22%20action=%22?%22%20的XXS误报，请各组核实一下，是否是误报

3、雷池发现攻击后填写EXECL格式的文本，已全部记录于safeline.txt中，只需要在EXECL中导入文本文件，然后选择‘空格’作为分隔符即可直接导入

4、360天眼流量传感器发现攻击后填写EXECL格式的文本，已全部记录于360skyeye.txt，只需要在EXECL中导入文本文件，然后选择‘空格’作为分隔符即可直接导入

使用方法：
1、为了方便记录次数，本程序已将当前时间改为手动设置，只需要设置如下一行中的时间，即可捕获从以下时间开始至今的所有攻击
run_time1 = datetime.datetime.strptime("2018-07-05 20:00:00", "%Y-%m-%d %H:%M:%S")

2、修改以下数字可以设置抓取至今为止的攻击条数
pagesize=50

3、本程序使用session运行，所以session过期后，请打开搜狗浏览器或谷歌浏览器中的开发者工具，刷新页面查找cookie后，将cookie粘贴到以下位置
headers = {
               'Cookie': 'csrftoken=gTPngeSoFTRg8cLpx1I9JxKdf9ibGcBAPZ4E8yPZCW1eXqAJWCIYKJRJ7DlXVUaM; sessionid=surfze305whe8xmcea0090owyksdn1aw',
               }