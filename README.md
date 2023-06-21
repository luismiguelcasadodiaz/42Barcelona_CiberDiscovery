# 42Barcelona_CiberDiscoveryvery

In my first day, I discovered that the knolewdge kidnnaps us, and carries us thru the long way and blinds us towardas short path.

After long technical discussions involving nslookup, RFC, protocols, ports and so on, that took us to nowhere, the solution was the web **"instant username"**, a web used to know username availability in differente social media platforms.

Another learning to take away was the usage of google lens to locate where, a photo with no gps metadata, has been shooted.


Directory listing is an Apache configuraiton Directive that instruct web server to show folder content when there is not index.htm or index.php file. When such configuration directive is not properly configured a **fuzzing attack** can be performed. Fuzzing is the art of automatic bug detection. The goal of fuzzing is to stress the application and cause unexpected behavior, resource leaks, or crashes. The process involves throwing invalid, unexpected, or random data as inputs at a computer. In this case we will test different regular path after the fully qiialified server name.

ctf.42barcelona.com:3318/admin
ctf.42barcelona.com:3318/content
ctf.42barcelona.com:3318/webdocs

A **path traversal** vulnerability allows an attacker to access files on your web server to which they should not have access. They do this by tricking either the web server or the web application running on it into returning files that exist outside of the web root folder.

You can check a web server foot print with

> curl -I http://ctf.42barcelona.com:3319/

```
HTTP/1.1 200 OK
Date: Tue, 20 Jun 2023 14:48:32 GMT
Server: Apache/2.4.54 (Ubuntu)
Last-Modified: Sun, 19 Feb 2023 16:48:29 GMT
ETag: "141-5f51050e4b140"
Accept-Ranges: bytes
Content-Length: 321
Vary: Accept-Encoding
Content-Type: text/html
```
I can see that it is a Apache server running on Ubuntu.

Which is the default Apache DocumentRoot folder?

/var/www/html

Which is an interesting file for reading while watching soap opera?
/etc/passwd

Then, navigating to http://ctf.42barcelona.com:3319/../../../etc/passwd would be a potential test for a path traversal attack

  ![Deeper knowledge Path traversal and a prevention technic.](https://portswigger.net/web-security/file-path-traversal)

  
