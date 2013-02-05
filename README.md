mod_dosdetector
===============

An apache module for detecting DoS attacks.
When detecting DoS attacks, this module set environment variables. Note that this module itself does not affect the response.

Install
-------

Just do make install

```
make install
```

Configuration
-------------

An sample configuration for mod_dosdetector.

```
LoadModule dosdetector_module modules/mod_dosdetector.so
LoadModule rewrite_module modules/mod_rewrite.so

<IfModule mod_dosdetector.c>
# enable the module
DoSDetection on
# DoSThreshold is the threshold for detecting 'soft' DoS attacks
DoSThreshold 5
# DoSHardThreshold is the threshold for detecting 'hard' DoS attacks
DoSHardThreshold 10
# DoSPeriod is the time window for counting requests
DoSPeriod 60
# DoSBanPeriod is the period to hold DoS state after a DoS detection
DoSBanPeriod 60
# DoSShmemName is the name of shared memory
DoSShmemName dosshm
# DoSTableSize is the table size to store ip addresses of clients
DoSTableSize 100
# Set DoSForwarded if you want to use X-Forwarded-For header for Remote Address
DoSForwarded on
# Set DoSIgnoreContentType if you want to ignore requests with some content-types
# Regular expression can be used
DoSIgnoreContentType image/*
</IfModule>

RewriteEngine on

# Redirect to some urls for requests detected as a soft DoS attack
RewriteCond  %{ENV:SuspectDoS} .+
RewriteRule .* http://example.com/ [P,L]

# Return 403 for requests detected as a hard DoS attack
RewriteCond  %{ENV:SuspectHardDoS} .+
RewriteCond %{REMOTE_ADDR} !^(192\.168\.0\.1)$
RewriteRule .* - [F,L]

RewriteLog logs/rewrite_log
RewriteLogLevel 0
```

Output to error logs
--------------------

When a request is detected as a DoS attack, the module output following logs.

```
[Sun Jul 1 13:46:48 2007] [notice] dosdetector: '127.0.0.1' is suspected as DoS attack! (counter: 181)
```

```
[Sun Jul 1 13:48:23 2007] [notice] dosdetector: '127.0.0.1' is suspected as Hard DoS attack! (counter: 361)
```
