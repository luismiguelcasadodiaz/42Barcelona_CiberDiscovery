# 42Barcelona_CiberDiscoveryvery

In my first day, I discovered that the knolewdge kidnnaps us, and carries us thru the long way and blinds us towards short path.

After long technical discussions involving nslookup, RFC, protocols, ports and so on, that took us to nowhere, the solution was the web **"instant username"**, a web used to know username availability in differente social media platforms.

Another learning to take away was the usage of google lens to locate where, a photo with no gps metadata, has been shooted.

#Directory listing and fuzzing

Directory listing is an Apache configuraiton Directive that instruct web server to show folder content when there is not index.htm or index.php file. When such configuration directive is not properly configured a **fuzzing attack** can be performed. Fuzzing is the art of automatic bug detection. The goal of fuzzing is to stress the application and cause unexpected behavior, resource leaks, or crashes. The process involves throwing invalid, unexpected, or random data as inputs at a computer. In this case we will test different regular path after the fully qiialified server name.

ctf.42barcelona.com:3318/admin
ctf.42barcelona.com:3318/content
ctf.42barcelona.com:3318/webdocs

#Path Traversal

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

Then, navigating to http://ctf.42barcelona.com:3319/../../../etc/passwd would be a potential test for a path traversal attack.


  [Deeper knowledge Path traversal and a prevention technic.](https://portswigger.net/web-security/file-path-traversal)

  
#**sql injection** 
SQL injection usually occurs when you ask a user for input, like their username/userid, and instead of a name/id, the user gives you an answer that front-end will unknowingly run on server database an SQL statement that extract information towards the attackant.

There is a potential dangers of using user input directly in in SQL statements.

A regular procedure like

```
txtUserId = getRequestString("UserId");
txtSQL = "SELECT * FROM Users WHERE UserId = " + txtUserId;
```

makes possible to the user transform it into:


|key|User name	|Password	|SQL Query                                                                  |
|---|-----------|---------|-------------------------------------------------------------------------- |
|1|tom	|tom	|SELECT * FROM users WHERE name='tom' and password='tom'|
|2|tom	|' or '1'='1	|SELECT * FROM users WHERE name='tom' and password='' or '1'='1'|
|3|tom	|' or 1='1	|SELECT * FROM users WHERE name='tom' and password='' or 1='1'|
|4|tom	|1' or 1=1 -- -	|SELECT * FROM users WHERE name='tom' and password='' or 1=1-- -'|
|5|' or '1'='1	|' or '1'='1	|SELECT * FROM users WHERE name='' or '1'='1' and password='' or '1'='1'|
|6|' or ' 1=1	|' or ' 1=1	|SELECT * FROM users WHERE name='' or ' 1=1' and password='' or ' 1=1'|
|7|1' or 1=1 -- -	|blah	|SELECT * FROM users WHERE name='1' or 1=1 -- -' and password='blah'|

THe key point here is to understand that in SQL exist a predence order in the logical operators. AND has precedence over OR.
That mean that in rows 2,3, and 4 above, no matter which is the password cause the expresion to the right of OR alwawys is TRUE.
If 'tom' exists as user, ` name='tom'` will evaluate to TRUE. TRUE and TRUE becomes TRUE. `SELECT` returns a row wiht all relevant data from tom.

In example 6 you will extract all data from users table. 

`name='' or ' 1=1' and password='' or ' 1=1'` becomes

`name='' or TRUE and password='' or TRUE`, that becomes

TRUE and TRUE.


[Too know more](https://portswigger.net/web-security/sql-injection)

[Common injection for user password](https://sechow.com/bricks/docs/login-1.html)


# Decoding
I had to refresh the difference between charset and encoding.

What is this i found in first exercise?
NDJCQ057YjQ1M182NF8xNV9jMDBsfQ==

it is made wiht a charset that contains upper (A-Z) (26 chars) , lower(a-z) (26 chars) , numbers (0-9) (10 chars)  and '='
 26 + 26 + 10 + 1 = 63, it is close to 64
[](https://en.wikipedia.org/wiki/Base64)
 

