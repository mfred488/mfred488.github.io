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

## Main objectives

Todo
