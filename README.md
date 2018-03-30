tornado异步代理 
====

代码原版为其他人所写，偶然搜索http connect方法格式时搜到的 .... 拿过来简化了下.......


代码比较简单，proxy作为Tcp中继在client和目标server两头读写，加了一些安全验证，主要是为了熟悉下connect方法


协议如下：

```Python
CONNECT www.web-tinker.com:80 HTTP/1.1
Host: www.web-tinker.com:80
Proxy-Connection: Keep-Alive
Proxy-Authorization: Basic *
Content-Length: 0

文本协议没什么说的 一般都能看懂, 需要记住的是 Basic后边的用户密码，必须要经过BASE64的编码
```

