# Awesome Log4Shell [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

A curated list of awesome links related to the [Log4Shell](https://security.snyk.io/vuln/SNYK-JAVA-ORGAPACHELOGGINGLOG4J-2314720) vulnerability.


## Contents

- [Explanation](#explanation)
- [Videos](#videos)
- [Vulnerable Software](#vulnerable-software)
- [Detection & Remediation](#detection--remediation)
- [Twitter Discussions](#twitter-discussions)
- [Examples & Proofs of Concept](#examples--proofs-of-concept)
- [Memes](#memes)
- [Contribute](#contribute)

## Explanation
- [MITRE CVE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228) - Official CVE page from MITRE.
- [Snyk Blog Writeup](https://snyk.io/blog/log4j-rce-log4shell-vulnerability-cve-2021-4428/) - Java Champion Brian Vermeer's in depth explanation of the Log4Shell vuln.
- [SANS](https://isc.sans.edu/diary/rss/28120) - Initiall analysis and [follow up](https://isc.sans.edu/diary/rss/28122).
- [Fastly Blog](https://www.fastly.com/blog/digging-deeper-into-log4shell-0day-rce-exploit-found-in-log4j) - Impact, how it works, and timeline.
- [Luna Sec](https://www.lunasec.io/docs/blog/log4j-zero-d) - Good tips for detection and remediation.
- [Tech Solvency](https://www.techsolvency.com/story-so-far/cve-2021-44228-log4j-log4shell/) - List of affected vendors and writeups.
- [Cado Security](https://www.cadosecurity.com/analysis-of-initial-in-the-wild-attacks-exploiting-log4shell-log4j-cve-2021-44228/) - Analysis of the attacks in the wild.
- [Rapid7](https://www.rapid7.com/blog/post/2021/12/10/widespread-exploitation-of-critical-remote-code-execution-in-apache-log4j/) - Analysis, remediation, and detection.
- [Cloudflare](https://blog.cloudflare.com/actual-cve-2021-44228-payloads-captured-in-the-wild/) - Cloudflare analysis of payloafds in the wild.
- [Exploiting JNDI injections in Java](https://www.veracode.com/blog/research/exploiting-jndi-injections-java) - Previous article on JNDI injection exploits.
- [SLF4J](http://slf4j.org/log4shell.html) - Comments from SLF4J project.
- [Understanding Log4Shell: vulnerability, attacks and mitigations](https://www.slideshare.net/BertJanSchrijver/understanding-log4shell-vulnerability-attacks-and-mitigations-250846006/) - Slide deck for webcast (see under [videos](#Videos)) by Roy van Rijn & Bert Jan Schrijver (OpenValue).

## Videos
- [CVE-2021-44228 - Log4j - MINECRAFT VULNERABLE! (and SO MUCH MORE)](https://www.youtube.com/watch?v=7qoPDq41xhQ) - John Hammond, Cybersecurity Researcher @HuntressLabs.
- [Blackhat2016 - JNDI manipulation to RCE Dream Land](https://www.youtube.com/watch?v=Y8a5nB-vy78) - Blackhat talk from 2016 describing the exploit path.
- [Understanding Log4Shell: vulnerability, attacks and mitigations](https://www.youtube.com/watch?v=TX1SF2dhMc4) - Webcast by Roy van Rijn & Bert Jan Schrijver (OpenValue).

## Vulnerable Software
- [NCSC-NL repository](https://github.com/NCSC-NL/log4shell/tree/main/software) - National Cyber Security Centrum list of vulnerable/non-vulnerable software.
- [Swithak](https://gist.github.com/SwitHak/b66db3a06c2955a9cb71a8718970c592) - List of vendor advisories related to log4shell.
- [Elastic](https://xeraa.net/blog/2021_mitigate-log4j2-log4shell-elasticsearch/) - Deep dive into which versions of Elastic are vulnerable and how to fix.
- [CISA](https://github.com/cisagov/log4j-affected-db) - CISA list of vulnerable software.

## Detection & Remediation 
- [Snyk Detection and Remediation](https://snyk.io/blog/find-fix-log4shell-quickly-snyk/) - Find and fix using Snyk.
- [Remediation cheat sheet](https://snyk.io/blog/log4shell-remediation-cheat-sheet/) - Remediation cheat sheet from Snyk.
- [Log4Shell Tester from Trendmicro](https://log4j-tester.trendmicro.com/) - Tool to determine vulnerability.
- [Curated Intelligence Trust Group](https://github.com/curated-intel/Log4Shell-IOCs) - Aggregated list of indicators of compromise feeds and threat reports.
- [Community Sourced Log4J Attack Surface](https://github.com/YfryTchsGD/Log4jAttackSurface) - List of Log4j attack vectors in popular manufacturers' products.
- [MSSP Alert](https://www.msspalert.com/cybersecurity-news/java-vulnerability-log4shell-zero-day-details-patches-and-updates/) - Good mitigation practices.
- [log4shell-detector](https://github.com/Neo23x0/log4shell-detector) - Checks logs for exploitation attempts.
- [Huntress vulnerability tester](https://log4shell.huntress.com/) - Web based tester.
- [Container scanners](https://hackmd.io/e9RUrXSwRKyERCOBDo96RA) - How to detect using container scanners.
- [Bash IOC scanner](https://github.com/Neo23x0/Fenrir) - Latest Fenrir supports checking for log4shell compromise and vulnerability.
- [Burp Plugin detector](https://blog.silentsignal.eu/2021/12/12/our-new-tool-for-enumerating-hidden-log4shell-affected-hosts/) - Burp plugin to detect vulnerable hosts.
- [Threatview IP list](https://github.com/Malwar3Ninja/Exploitation-of-Log4j2-CVE-2021-44228) - List of IP addresses currently exploiting log4shell.
- [LizardLabs query tool](https://github.com/lizardlabs/Log-Parser-Lizard-Queries/blob/master/queries/log4shell/log4shell.search.MD5.sql) - Search for vulnerable jar files using MS Log Parser.
- [Canary tokens](https://help.canary.tools/hc/en-gb/articles/4413465229201) - Use a canary token to test for vulnerable systems.
- [Exploit Strings data](https://github.com/rapid7/data/tree/master/log4shell/heisenberg) - JNDI exploit strings seen in the wild by Rapid7.
- [log4j-detector](https://github.com/mergebase/log4j-detector) - Detects vulnerable log4j versions on your file-system within any application.
- [Mitigate attacks using Nginx](https://www.infiniroot.com/blog/1155/using-nginx-lua-script-mitigate-log4shell-cve-2021-44228-vulnerability) - A simple and effective way to use Nginx (using a Lua block) to protect against attacks.
- [OWASP Core Rule Set](https://coreruleset.org/20211213/crs-and-log4j-log4shell-cve-2021-44228/) - Modsecurity CRS rules.
- [AWS daemonset](https://github.com/aws-samples/kubernetes-log4j-cve-2021-44228-node-agent) - Daemonset from AWS to mitigate vulnerable instances in Kubernetes.
- [Hotpatch tool](https://github.com/corretto/hotpatch-for-apache-log4j2) - JVM level hotpatch tool from AWS

## Twitter Discussions
- [Log4Shell spreadsheet](https://twitter.com/GossiTheDog/status/1470056396968374273?s=20) - Spreadsheet for defenders listing vendors and products.

## Examples & Proofs of Concept

- [Log4Shell PoC](https://github.com/snyk-labs/log4shell-poc) - Full stack demo including Java LDAP and HTTP servers and vulnerable Java client.
- [Log4Shell vulnerable Java application](https://github.com/christophetd/log4shell-vulnerable-app) - Spring Boot web application vulnerable to Log4shell for easy reproduction.

## Memes
- [Log4J memes](https://github.com/snyk-labs/awesome-log4shell/blob/main/Log4Jmemes.md) - Sometimes we still need a smile. 

## Contribute
Contributions welcome! Read the [contribution guidelines](contributing.md) first.
