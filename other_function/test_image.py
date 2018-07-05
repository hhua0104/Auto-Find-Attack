#-*- coding:utf-8 -*-
import Image, ImageDraw, ImageFont, ImageFilter
import random

ttfont = ImageFont.truetype("Arial.ttf",13)
im = Image.open("image.jpg")
draw = ImageDraw.Draw(im)
draw.text((10,10),u'www.sd.sgcc.com.cn//plus/download.php?open=1&arrs1[]=99&arrs1[]=102&arrs1[]=103&arrs1[]=95&arrs1[]=100&arrs1[]=98&arrs1[]=112&arrs1[]=1', fill=(0,0,0),font=ttfont)
draw.text((10,40),unicode('高危请求','utf-8'), fill=(0,0,0),font=ttfont)
#im.show()
im.save('code1.jpg', 'jpeg');