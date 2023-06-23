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

## Exercise one

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

## Exercise two 
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

### First approach
OSINT suggested that hashcat would be a good tool
With this [Hashcat beginners guide] (https://resources.infosecinstitute.com/topic/hashcat-tutorial-beginners/) i started the job.

To know  hash modes **available** at Hashcat tool `Hashcat -h | grep 160` 
| Mode      | Name                                                      |usage|
|----------|------------------------------------------------------------|------|
|   6000 | RIPEMD-160                                                 | Raw Hash|
|    160 | HMAC-SHA1 (key = $salt)                                    | Raw Hash authenticated|
|   1600 | Apache $apr1$ MD5, md5apr1, MD5 (APR)                      | FTP, HTTP, SMTP, LDAP Server|


To know potential hash modes that suit the hash to decyper use `hashcat --show target.txt`

The following 7 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
    100 | SHA1                                                       | Raw Hash
   6000 | RIPEMD-160                                                 | Raw Hash
    170 | sha1(utf16le($pass))                                       | Raw Hash
   4700 | sha1(md5($pass))                                           | Raw Hash salted and/or iterated
  18500 | sha1(md5(md5($pass)))                                      | Raw Hash salted and/or iterated
   4500 | sha1(sha1($pass))                                          | Raw Hash salted and/or iterated
    300 | MySQL4.1/MySQL5                                            | Database Server



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


hashcat -m 100 -a 0  target.txt wordlist.txt

hashcat -m 170 -a 0  target.txt wordlist.txt

hashcat -m 300 -a 0  target.txt wordlist.txt

hashcat -m 4500 -a 0  target.txt wordlist.txt

hashcat -m 4700 -a 0  target.txt wordlist.txt

hashcat -m 18500 -a 0  target.txt wordlist.txt


Gave me no results on Thursday

Antonio Gull, next day, teached me that i had to repeat the argument wordlist and change the attack mode from Straight (0) to combination(1)

`hashcat -m 100 -a 1 target.txt wordlist.txt wordlist.txt`

```
hashcat (v6.2.6) starting

METAL API (Metal 212.8)
=======================
* Device #1: AMD Radeon Pro 570X, skipped

OpenCL API (OpenCL 1.2 (Jun  8 2020 17:36:15)) - Platform #1 [Apple]
====================================================================
* Device #2: Intel(R) Core(TM) i5-8500 CPU @ 3.00GHz, 4064/8192 MB (1024 MB allocatable), 6MCU
* Device #3: AMD Radeon Pro 570X Compute Engine, skipped

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Dictionary cache hit:
* Filename..: wordlist.txt
* Passwords.: 9
* Bytes.....: 52
* Keyspace..: 9

Dictionary cache hit:
* Filename..: wordlist.txt
* Passwords.: 9
* Bytes.....: 52
* Keyspace..: 9

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 100c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: wordlist.txt
* Passwords.: 9
* Bytes.....: 52
* Keyspace..: 81

The wordlist or mask that you are using is too small.
This means that hashcat cannot use the full parallel power of your device(s).
Unless you supply more work, your cracking speed will drop.
For tips on supplying more work, see: https://hashcat.net/faq/morework

Approaching final keyspace - workload adjusted.
```
c967d488512ab5559b446f97843de1be0d615088:**liamup2u**
```
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 100 (SHA1)
Hash.Target......: c967d488512ab5559b446f97843de1be0d615088
Time.Started.....: Fri Jun 23 13:25:04 2023 (0 secs)
Time.Estimated...: Fri Jun 23 13:25:04 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (wordlist.txt), Left Side
Guess.Mod........: File (wordlist.txt), Right Side
Speed.#2.........:   778.8 kH/s (0.01ms) @ Accel:512 Loops:9 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 81/81 (100.00%)
Rejected.........: 0/81 (0.00%)
Restore.Point....: 0/9 (0.00%)
Restore.Sub.#2...: Salt:0 Amplifier:0-9 Iteration:0-9
Candidate.Engine.: Device Generator
**Candidates.#2....: liamliam -> up2uup2u**
Hardware.Mon.SMC.: Fan0: 44%
Hardware.Mon.#2..: Temp: 46c

Started: Fri Jun 23 13:25:01 2023
Stopped: Fri Jun 23 13:25:06 2023
```



### Second approach

I tested the alternative subject hinted **John the ripper**

Inside an ubuntu virtualbox artifact i compiled,  from latest source version [folllowing instructions](https://github.com/openwall/john/blob/bleeding-jumbo/doc/INSTALL-UBUNTU) 

my first try `./john   --wordlist=wordlist.txt   crack.txt` produced:

```
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-AxCrypt"
Use the "--format=Raw-SHA1-AxCrypt" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-Linkedin"
Use the "--format=Raw-SHA1-Linkedin" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "ripemd-160"
Use the "--format=ripemd-160" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "has-160"
Use the "--format=has-160" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "raw-SHA1-opencl"
Use the "--format=raw-SHA1-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 256/256 AVX2 8x])
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
0g 0:00:00:00 DONE (2023-06-22 20:43) 0g/s 180.0p/s 180.0c/s 180.0C/s up2u
```

testing all warnings...

```
./john  --wordlist=wordlist.txt  --format=Raw-SHA1-AxCrypt  crack.txt

Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1-AxCrypt [SHA1 256/256 AVX2 8x])
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
0g 0:00:00:00 DONE (2023-06-22 20:45) 0g/s 180.0p/s 180.0c/s 180.0C/s up2u
Session completed.
```

```
./john  --wordlist=wordlist.txt  --format=Raw-SHA1-Linkedin  crack.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1-Linkedin [SHA1 256/256 AVX2 8x])
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
0g 0:00:00:00 DONE (2023-06-22 20:47) 0g/s 180.0p/s 180.0c/s 180.0C/s up2u
```

```
./john  --wordlist=wordlist.txt  --format=ripemd-160  crack.txt
Using default input encoding: UTF-8
Loaded 1 password hash (ripemd-160, RIPEMD 160 [32/64])
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
0g 0:00:00:00 DONE (2023-06-22 20:47) 0g/s 225.0p/s 225.0c/s 225.0C/s liam..up2u
Session completed.

```

```
./john  --wordlist=wordlist.txt  --format=has-160  crack.txt
Using default input encoding: UTF-8
Loaded 1 password hash (has-160 [HAS-160 32/64])
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
0g 0:00:00:00 DONE (2023-06-22 20:48) 0g/s 180.0p/s 180.0c/s 180.0C/s liam..up2u
Session completed.
```

I wrongly concluded that password was liam and up2u. Eduard vendrell alerted me that it was imposiible to get an awswer so fast.

He suffered same problem till he modified inside john.conf the default wordlist file.

Apparently `--wordlist=wordlist.txt` does not work correctly form CLI.

I tried again and got a tottaly differente output
```
./john   --format=raw-sha1   crack.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 256/256 AVX2 8x])
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:./wordlist.lst
Enabling duplicate candidate password suppressor
0g 0:00:00:01 DONE 2/3 (2023-06-23 13:10) 0g/s 15531p/s 15531c/s 15531C/s pain..Hacking38
Proceeding with incremental:ASCII
Disabling duplicate candidate password suppressor
```


[I hashed it again at] (http://www.sha1-online.com/) and i got the hash the subject proposes.

hashcat --show target.txt



<img width="992" alt="Screen Shot 2023-06-23 at 2 19 11 PM" src="https://github.com/luismiguelcasadodiaz/42Barcelona_CiberDiscovery/assets/19540140/9636223a-a4d0-45af-a3a4-01e86dabd70b">



