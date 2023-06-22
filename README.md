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
 26 + 26 + 10 + 1 = 63, it is close to 64.
 
[Una buena explicación de la codificacion Base 64](https://en.wikipedia.org/wiki/Base64)

Gracias a Carlos Mosquera he aprendido a decodificar base64 con la línea de comandos

`echo '4e 44 4a 43 51 30 35 37 59 6a 51 31 4d 31 38 32 4e 46 38 78 4e 56 39 6a 4d 44 42 73 58 32 4a 31 4e 31 39 6f 4d 33 68 66 4d 54 56 66 59 7a 41 77 62 44 4e 79 66 51 3d 3d' | xxd -r -p | base64 -d`
 
# Hashing
As the only way to revert a hash is to find a text that generates the same hash i googled for some hint.

When you know someting about the structure of what you are looking for you can accelate the discovery process.

From the web [Cyber Chef] (https://gchq.github.io/CyberChef/) is possible to obtain a hash analysys that helps you reduce the search/reversal scope.

```

Hash length: 32
Byte length: 16
Bit length:  128

Based on the length, this hash could have been generated by one of the following hashing functions:
MD5
MD4
MD2
HAVAL-128
RIPEMD-128
Snefru
Tiger-128
```
with this knowledge  i looked for [A MD5 reversal hash tool](https://www.md5online.org/md5-decrypt.html)


For the second exercise, a hash of 40 chars

`c967d488512ab5559b446f97843de1be0d615088`

cyber chef hinted me with:

```
Hash length: 40
Byte length: 20
Bit length:  160

Based on the length, this hash could have been generated by one of the following hashing functions:
SHA-1
SHA-0
FSB-160
HAS-160
HAVAL-160
RIPEMD-160
Tiger-160
```


OSINT suggested that hashcat would be a good tool
With this [Hashcat beginners guide] (https://resources.infosecinstitute.com/topic/hashcat-tutorial-beginners/) i started the job.

Hashcat -h | grep 160 

   **6000 | RIPEMD-160                                                 | Raw Hash**
    160 | HMAC-SHA1 (key = $salt)                                    | Raw Hash authenticated
   1600 | Apache $apr1$ MD5, md5apr1, MD5 (APR)                      | FTP, HTTP, SMTP, LDAP Server

[Examples of hashes by method]   (https://hashcat.net/wiki/doku.php?id=example_hashes)

After filtering by hash's length it seems that only a reduced set of hash methods generate a digest with a lenght of 40

|Hash-Mode	|Hash-Name|	Example	|Lenght|
|-----------|---------|---------|------|
|100	|SHA1	|b89eaac7e61417341b710b727768294d0e6a277b|	40|
|170	|sha1(utf16le($pass))	|b9798556b741befdbddcbf640d1dd59d19b1e193|	40|
|300	|MySQL4.1/MySQL5	|fcf7c1b8749cf99d88e5f34271d636178fb5d130|	40|
|4500	|sha1(sha1($pass))	|3db9184f5da4e463832b086211af8d2314919951|	40|	
|4700	|sha1(md5($pass))	|92d85978d884eb1d99a51652b1139c8279fa8663|	40|
|6000	|RIPEMD-160	|012cb9b334ec1aeb71a9c8ce85586082467f7eb6|	40|
|18500|	sha1(md5(md5($pass)))	|888a2ffcb3854fba0321110c5d0d434ad1aa2880|	40|

In Slack channel, staff suggested us a word list to try with

|**word**|
|--------|
|liam|
|42|
|barcelona|
|up2u|
|1978|
|lion|
|spain|
|hacking|


hashcat -m 100 -a 0 -S target.txt wordlist.txt
hashcat -m 170 -a 0 -S target.txt wordlist.txt
hashcat -m 300 -a 0 -S target.txt wordlist.txt
hashcat -m 4500 -a 0 -S target.txt wordlist.txt
hashcat -m 4700 -a 0 -S target.txt wordlist.txt
hashcat -m 18500 -a 0 -S target.txt wordlist.txt

gave me no results.
