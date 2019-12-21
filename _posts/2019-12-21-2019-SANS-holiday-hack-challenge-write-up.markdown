---
layout: post
title:  "2019 SANS Holiday Hack Challenge write-up"
date:   2019-12-20
categories: security
---

For the past couple of years, SANS has spoiled us with an excellent annual "Holiday hack challenge".

## The elves

Similarily to the previous editions, the elves faces some relatively easy issues. If we manage to help them, they'll throw us some pretty useful hints for the main objectives.
So let's solve their problem first!

### Bushy Evergreen

In the lobby, Bushy is stuck in an opened `ed` session.
A quick look at [ed documentation](https://www.gnu.org/software/ed/manual/ed_manual.html) lets us know that `q` is the command we're looking for.

### Tangle Coalbox

After getting into the courtyard and heading east, we meet Tangle who needs to guess the keypad's 4-digits code.
{% highlight python %}
print("Re-type the python script here")
{% endhighlight %}

### Kent Tinseltooth

Now, heading north, we enter into the students union building and meet Kent, who's struggling with iptables. He wants to configure his firewall rules as follow;
1. Set the default policies to DROP for the INPUT, FORWARD, and OUTPUT chains.
2. Create a rule to ACCEPT all connections that are ESTABLISHED,RELATED on the INPUT and the OUTPUT chains.
3. Create a rule to ACCEPT only remote source IP address 172.19.0.225 to access the local SSH server (on port 22).
4. Create a rule to ACCEPT any source IP to the local TCP services on ports 21 and 80.
5. Create a rule to ACCEPT all OUTPUT traffic with a destination TCP port of 80.
6. Create a rule applied to the INPUT chain to ACCEPT all traffic from the lo interface.

`iptables` syntax is pretty straightforward, and there's no trick here. The five first rules can be directly adapted from the rules given in [the hint](https://upcloud.com/community/tutorials/configure-iptables-centos/), but for the last one, we'll need the option `-i` which is not mentioned there:

{% highlight bash %}
# Set the default policies to DROP for the INPUT, FORWARD, and OUTPUT chains.
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT DROP

# Create a rule to ACCEPT all connections that are ESTABLISHED,RELATED on the INPUT and the OUTPUT chains.
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Create a rule to ACCEPT only remote source IP address 172.19.0.225 to access the local SSH server (on port 22).
sudo iptables -A INPUT -p tcp --dport 22 -s 172.19.0.225 -j ACCEPT

# Create a rule to ACCEPT any source IP to the local TCP services on ports 21 and 80.
sudo iptables -A INPUT -p tcp --dport 21 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# Create a rule to ACCEPT all OUTPUT traffic with a destination TCP port of 80.
sudo iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT

# Create a rule applied to the INPUT chain to ACCEPT all traffic from the lo interface.
sudo iptables -A INPUT -i lo -j ACCEPT
{% endhighlight %}

It can take a few seconds for the game to detect that the firewalling rules are ok.

### SugarPlum Mary

Let's now get out of the building, and head east to the Hermey Hall. Right in front of us stands SugarPlum Mary, who just wants to list the files in in home directory.
Someone played a trick on him, and running `ls` justs output: `This isn't the ls you're looking for`

So which `ls` is actually used here?
{% highlight bash %}
$ which ls
/usr/local/bin/ls
{% endhighlight %}

A quick look at [the filesystem hierachy](https://en.wikipedia.org/wiki/Filesystem_Hierarchy_Standard) tells us that something as essential as `ls` should be in `/bin`.
And indeed, `/bin/ls` is there and correctly lists the files in our friend's home directory.

### Alabaster Snowball

Let's now go into the Speaker UNpreparedness Room, where we meet Alabaster. This elf wants to log in (using his completely secure login and passwords), and land into in a Bash shell. As you probably guessed, the natural way (`sudo alabaster_password`) will not exactly work (but you should definitely try first).

As mentioned in the hints, the users shell is determined by the contents of /etc/passwd
{% highlight bash %}
$ cat /etc/passwd | grep alabaster_snowball
alabaster_snowball:x:1001:1001::/home/alabaster_snowball:/bin/nsh
{% endhighlight %}

`/bin/nsh` does not look like a legit shell. Let's have a first look at it:
{% highlight bash %}
$ ls -larth /bin/nsh
-rwxrwxrwx 1 root root 74K Dec 11 17:40 /bin/nsh
{% endhighlight %}

Oh wow! Free for all! Let's just replace it with `/bin/bash` then:
{% highlight bash %}
$ cp /bin/bash /bin/nsh
cp: cannot create regular file '/bin/nsh': Operation not permitted
{% endhighlight %}

That's not what I expected. Please not that the error message is not `Permission denied`: this is NOT a permission issue. A little bit of Googling shows us that this error message comes up when one tries to remove/alter an [immutable file](https://www.tecmint.com/make-file-directory-undeletable-immutable-in-linux/).
This requires root permissions though. But fortunately, runnin `sudo -l` shows that our current user can run `chattr` as root!

{% highlight bash %}
$ sudo chattr -i /bin/nsh
$ cp /bin/bash /bin/nsh
$ su alabaster_snowball
Password:
Loading, please wait......



You did it! Congratulations!
{% endhighlight %}

### Holy Evergeen

We're done with the Speaker UNpreparedness Room; let's get out, and step into the Netwars room. Here we're greeted by Holly Evergreen, who is unable to find his way to the exam solutions stored in Mongo.

{% highlight bash %}
$ mongo
MongoDB shell version v3.6.3
connecting to: mongodb://127.0.0.1:27017
2019-12-20T21:42:53.525+0000 W NETWORK  [thread1] Failed to connect to 127.0.0.1:27017, in(checkin
g socket for error after poll), reason: Connection refused
2019-12-20T21:42:53.525+0000 E QUERY    [thread1] Error: couldn't connect to server 127.0.0.1:2701
7, connection attempt failed :
connect@src/mongo/shell/mongo.js:251:13
@(connect):1:6
exception: connect failed
{% endhighlight %}

So `mongod` is either not running on this machine, or not listening on the default port 27017. We can try to find the listening port of `mongod` using netstat, but we'll need to be root... Let's see what we can do:
{% highlight bash %}
$ sudo -l
User elf may run the following commands on f12e9b6f53e3:
    (mongo) NOPASSWD: /usr/bin/mongod --quiet --fork --port 12121 --bind_ip 127.0.0.1
        --logpath\=/tmp/mongo.log
    (root) SETENV: NOPASSWD: /usr/bin/python /updater.py
{% endhighlight %}

Funny: we can see here the port used by `mongod` :) Let's connect to the database server which listens on port 12121: `mongo localhost:12121`

For those familiar with SQL and not familiar with Mongo, Mongo provides a ["mapping chart"](https://docs.mongodb.com/manual/reference/sql-comparison/) that can help to "translate" Mongo concepts into their SQL counterpart.

{% highlight javascript %}
> db
test
> show collections
redherring
> db.redherring.find()
{ "_id" : "This is not the database you're looking for." }
> show dbs
admin   0.000GB
config  0.000GB
elfu    0.000GB
local   0.000GB
test    0.000GB
> use elfu
switched to db elfu
> show collections
bait
chum
line
metadata
solution
system.js
tackle
tincan
> db.solution.find()
{ "_id" : "You did good! Just run the command between the stars: ** db.loadServerScripts();displaySolution(); **" }
{% endhighlight %}


The first database we landed in (`test`) does not contain much, so we switch to the more promising `elfu` database, and see an appealing collection named `solution`. It contains only one document, which gives us the key of this enigma. Running this last command `db.loadServerScripts();displaySolution();` in the mongo shell will unlock the solution!

### Sparkle Redberry
Only one to go! Let's get out of the Netwars room, and enter the laboratory. Sparkle Redberry is waiting near the computer-piloted laser, with the hardest elf challenge (in my opinion). Looking at the number of people standing in the room at the time I'm writing this, I believe I'm not the only one who struggled with this one.

TODO picture here

Note: I was a bit reluctant to code using PowerShell at first. But this challenge is actually not trivial, and I don't think one can complete it by adapting PowerShell one-liners found on Stackoverflow. Hence I learned a bit of PowerShell for this, and I'm glad I did: the language is consistent, well documented, and often feels way cleaner than the shell script I usually write on Unix.

Let's start! As advised in the welcome message, let's have a look at the laser-controlling API description:
{% highlight powershell %}
(Invoke-WebRequest -Uri http://localhost:1225/).RawContent
...
----------------------------------------------------
Christmas Cheer Laser Project Web API
----------------------------------------------------
Turn the laser on/off:
GET http://localhost:1225/api/on
GET http://localhost:1225/api/off

Check the current Mega-Jollies of laser output
GET http://localhost:1225/api/output

Change the lense refraction value (1.0 - 2.0):
GET http://localhost:1225/api/refraction?val=1.0

Change laser temperature in degrees Celsius:
GET http://localhost:1225/api/temperature?val=-10

Change the mirror angle value (0 - 359):
GET http://localhost:1225/api/angle?val=45.1

Change gaseous elements mixture:
POST http://localhost:1225/api/gas
POST BODY EXAMPLE (gas mixture percentages):
O=5&H=5&He=5&N=5&Ne=20&Ar=10&Xe=10&F=20&Kr=10&Rn=10
{% endhighlight %}

There are 4 parameters that can be set using the API, and we need to find the optimal value for each and every one of them in order to get an output of more than 5 Mega-Jollies!

#### Mirror angle value
The riddle starts with the file `/home/callingcard.txt`, as hinted in the message displayed when we log in:

{% highlight powershell %}
PS /home/elf> Get-Content /home/callingcard.txt
What's become of your dear laser?
Fa la la la la, la la la la
Seems you can't now seem to raise her!
Fa la la la la, la la la la
Could commands hold riddles in hist'ry?
Fa la la la la, la la la la
Nay! You'll ever suffer myst'ry!
Fa la la la la, la la la la
{% endhighlight %}

History... Indeed, it's always good to look at the command history to start a scavenging hunt! In PowerShell, we'll do that using the cmdlet `Get-History`

{% highlight powershell %}
PS /home/elf> Get-History

  Id CommandLine
  -- -----------
   1 Get-Help -Name Get-Process
   2 Get-Help -Name Get-*
   3 Set-ExecutionPolicy Unrestricted
   4 Get-Service | ConvertTo-HTML -Property Name, Status > C:\services.htm
   5 Get-Service | Export-CSV c:\service.csv
   6 Get-Service | Select-Object Name, Status | Export-CSV c:\service.csv
   7 (Invoke-WebRequest http://127.0.0.1:1225/api/angle?val=65.5).RawContent
   8 Get-EventLog -Log "Application"
   9 I have many name=value variables that I share to applications system wide. At a command I w…
  10 (Invoke-WebRequest -Uri http://localhost:1225/).RawContent
  11 Get-Content /home/callingcard.txt
{% endhighlight %}

There we go! We can see that someone has set the mirror angle value using the Web API (command 7) to *65.5 degrees*.

#### Lense refraction

We also notice a weird command 9. Let's have a deeper look into this one:

{% highlight powershell %}
PS /home/elf> ( Get-History -Id 9 ).CommandLine
I have many name=value variables that I share to applications system wide. At a command I will rev
eal my secrets once you Get my Child Items.
{% endhighlight %}

This description reminds me of environment variables. These are certainly available in PowerShell too, right ...? [Yep they are!](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables?view=powershell-6) Let's list them:
{% highlight powershell %}
PS /home/elf> Set-Location Env:
PS Env:/> Get-ChildItem

Name                           Value
----                           -----
_                              /bin/su
DOTNET_SYSTEM_GLOBALIZATION_I… false
HOME                           /home/elf
HOSTNAME                       02ecb3c03407
LANG                           en_US.UTF-8
LC_ALL                         en_US.UTF-8
LOGNAME                        elf
MAIL                           /var/mail/elf
PATH                           /opt/microsoft/powershell/6:/usr/local/sbin:/usr/local/bin:/usr/s…
PSModuleAnalysisCachePath      /var/cache/microsoft/powershell/PSModuleAnalysisCache/ModuleAnaly…
PSModulePath                   /home/elf/.local/share/powershell/Modules:/usr/local/share/powers…
PWD                            /home/elf
RESOURCE_ID                    a5aaabcd-2574-4b9b-bbf4-cf2927201e5e
riddle                         Squeezed and compressed I am hidden away. Expand me from my priso…
SHELL                          /home/elf/elf
SHLVL                          1
TERM                           xterm
USER                           elf
USERDOMAIN                     laserterminal
userdomain                     laserterminal
USERNAME                       elf
username                       elf
{% endhighlight %}

The variable named `riddle` smells like a hint. Its content is:
> Squeezed and compressed I am hidden away. Expand me from my prison and I will show you the way. Recurse through all /etc and Sort on my LastWriteTime to reveal im the newest of all.

No need to be smart here: let's get the most recently updated file in `/etc`. This can be done by:
* Listing all the files in `/etc` (and its subfolders): this can be done using the cmdlet `Get-ChildItem` with the option `-Recurse`
* Sort them by last edition date: this can be done using the cmdlet [`Sort-Object`](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/sort-object?view=powershell-6)
* And only keeping the last one: this can be done using `Select-Object` with the option `-Limit`


{% highlight powershell %}
> Get-ChildItem -Path /etc -Recurse | Sort-Object LastWriteTime | Select-Object -Last 1

    Directory: /etc/apt

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
--r---          12/20/19 11:20 PM        5662902 archive
{% endhighlight %}

This tells us that the last edited file in `/etc` is `/etc/apt/archive`. Based on its name, it's an archive, which adds up with the previous hint. Let's try to see what inside! The cmdlet `Expand-Archive` allows us to uncompress it:

{% highlight powershell %}
PS /home/elf> Expand-Archive -LiteralPath /etc/apt/archive -DestinationPath /home/elf
PS /home/elf> Get-ChildItem ./refraction/

    Directory: /home/elf/refraction
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
------           11/7/19 11:57 AM            134 riddle
------           11/5/19  2:26 PM        5724384 runme.elf
{% endhighlight %}

The file `runme.elf` is a binary file; looking at its first bytes, it looks like a x86-64 [ELF file](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#File_header):
{% highlight powershell %}
PS /home/elf> Get-Content ./refraction/runme.elf | format-hex | Select-Object -First 1


                       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
00000000000000000000   7F 45 4C 46 02 01 01 00 00 00 00 00 00 00 00 00  ELF............
00000000000000000010   02 00 3E 00 01 00 00 00 75 1A 40 00 00 00 00 00  ..>.....u.@.....
...
{% endhighlight %}

It's not possible to execute the file as it is though. Trying to do so will yield a very obscure error. I actually spent quite some time here, until I realized that `chmod` was the only binary I could use in `/bin`. So I tried to make `runme.elf` executable using `chmod`, and it worked!

{% highlight powershell %}
> ./runme.elf
Program 'runme.elf' failed to run: No such file or directoryAt line:1 char:1
+ ./runme.elf
+ ~~~~~~~~~~~.
At line:1 char:1
+ ./runme.elf
+ ~~~~~~~~~~~
+ CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
+ FullyQualifiedErrorId : NativeCommandFailed

> chmod +x ./runme.elf
> ./runme.elf
refraction?val=1.867
{% endhighlight %}

And here is our second parameter! The lense refraction must be set to *1.867*.

#### Temperature

When we un-compressed the archive in the step above, we not only obtained the ELF file, but also a riddle:
> Very shallow am I in the depths of your elf home. You can find my entity by using my md5 identity:
>
> 25520151A320B5B0D21561F92C8F6224

We can brute-force our way in, by looking at every file in the folder `/home/elf/depths` (recursively), computing its MD5 digest, and comparing it with the given value.

{% highlight powershell %}
> $files = Get-ChildItem -Path ./depths/ -Recurse
> foreach ($file in $files) {
        if ((Get-Item $file) -is [System.IO.DirectoryInfo]) {
            continue;
        }
        $hash = (Get-FileHash $file -Algorithm MD5 -ErrorAction SilentlyContinue)
        if (!($hash -eq $null) -and ($hash.Hash.Contains("25520151A320B5B0D21561F92C8F6224"))) {
            echo "$file"
        }
    };
/home/elf/depths/produce/thhy5hll.txt

> Get-Content /home/elf/depths/produce/thhy5hll.txt
temperature?val=-33.5
I am one of many thousand similar txt's contained within the deepest of /home/elf/depths. Finding
me will give you the most strength but doing so will require Piping all the FullName's to Sort Len
gth.
{% endhighlight %}

We got the third parameter: the temperature must be set to -33.5.

#### Gas composition

The fourth and last parameter will require several steps. Let's start from the hint that was given together with the temperature value:

>I am one of many thousand similar txt's contained within the deepest of /home/elf/depths. Finding
>me will give you the most strength but doing so will require Piping all the FullName's to Sort Length.

We want to find the *deepest* files in `./depth`: we can do that by:
* Looping over all the files in `./depth`
* For each file, compute a new field called `Depth`, which is the length of it's attribute `FullName`. [This can be done using Select-Object](https://4sysops.com/archives/add-a-calculated-property-with-select-object-in-powershell/).
* Then sort the files by Depth, and keeps the 2 deepest file (just in case there's an ex-aequo).

Translated into PowerShel:
{% highlight powershell %}
Get-ChildItem -Path ./depths -Recurse | Select-Object FullName, @{Name = 'Depth'; Expression = {$_.FullName.Length}} | sort Depth | Select-Object -Last 2 | Format-List -Property *
    FullName : /home/elf/depths/larger/cloud/behavior/beauty/enemy/produce/age/chair/unknown/
               escape/vote/long/writer/behind/ahead/thin/occasionally/explore/tape/wherever/p
               ractical/therefore/cool/plate/ice/play/truth/potatoes/beauty/fourth/careful/da
               wn/adult/either/burn/end/accurate/rubbed/cake/main/she/threw/eager/trip/to/soo
               n/think/fall/is/greatest/become/accident/labor/sail/dropped/cjfuro1d.txt
    Depth    : 384

    FullName : /home/elf/depths/larger/cloud/behavior/beauty/enemy/produce/age/chair/unknown/
               escape/vote/long/writer/behind/ahead/thin/occasionally/explore/tape/wherever/p
               ractical/therefore/cool/plate/ice/play/truth/potatoes/beauty/fourth/careful/da
               wn/adult/either/burn/end/accurate/rubbed/cake/main/she/threw/eager/trip/to/soo
               n/think/fall/is/greatest/become/accident/labor/sail/dropped/fox/0jhj5xz6.txt
    Depth    : 388
{% endhighlight %}

Here is our file! But we're not there yet: the file contains another riddle.
{% highlight powershell %}
Get-Content /home/elf/depths/.../fox/0jhj5xz6.txt
Get process information to include Username identification. Stop Process to show me you're skilled and in this order they must be killed:

bushy
alabaster
minty
holly

Do this for me and then you /shall/see
{% endhighlight %}

(Please note that the content of the file will actually change for each and every attempt)

We need to kill the process belonging to the user listed below *in the correct order*. Nothing complicated here, as `Get-Process` (with the option `-IncludeUserName`) will let us list the ongoing processes and the user who started them. Once the process are killed, the file `/shall/see` becomes readable:

{% highlight powershell %}
Get-Process -IncludeUserName

     WS(M)   CPU(s)      Id UserName                       ProcessName
     -----   ------      -- --------                       -----------
     28.73     1.74       6 root                           CheerLaserServi
    214.16    30.30      31 elf                            elf
      3.52     0.02       1 root                           init
      0.75     0.00      25 bushy                          sleep
      0.78     0.00      26 alabaster                      sleep
      0.83     0.00      27 minty                          sleep
      0.73     0.00      29 holly                          sleep
      3.25     0.00      30 root                           su

Stop-Process 25
Stop-Process 26
Stop-Process 27
Stop-Process 29
Get-Content /shall/see
Get the .xml children of /etc - an event log to be found. Group all .Id's and the last thing will be in the Properties of the lonely unique event Id.
{% endhighlight %}

Another riddle?!

{% highlight powershell %}
{% endhighlight %}


## Main objectives

Todo
