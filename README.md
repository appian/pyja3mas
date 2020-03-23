# PyJA3mas

### Background Information

When a client connects to a server via HTTPS, it utilizes SSL/TLS to create the
secure connection.  Each client can complete the TLS handshake in various ways,
and the [JA3](https://github.com/salesforce/ja3) fingerprinting algorithm is
meant to uniquely identify certain clients.  With this fingerprint, we can
identify specific clients on the network from a single network connection.  We
are able to identify everyday applications, such as Google Chrome or Firefox,
as well as unique or potentially malicious clients, such as custom malware that
is propagating through the network.  This lightweight server makes it easy to
identify these applications.


### How the HTTPS Server Works
`https_server.py` contains a barebones Python concurrent HTTPS server that
maintains the minimum connection time to digest the JA3 fingerprint from the
browser client.

It utilizes Polling to create a concurrent web server.  When a client connects
to the server, it looks for the main GET request after the TLS handshake takes
place.  After this, the web server returns the JA3 fingerprint, as well as the
browser client/version that it parses from the User-Agent string along with the
GET request.

When the server gets a new client or JA3, it logs it to STDOUT, as well as the log file.


### Running the Server
Running the server is very easy and straightforward.  To install all of the requirements, run

```
pip3 install -r requirements.txt
```
Next, you will need to generate certificates for the https server to use:
```
openssl req -newkey rsa:4096 -nodes -keyout privkey.pem -x509 -days 365 -out fullchain.pem
```

Place these two `.pem` files in a directory called `certs/` for seamless use
with the https server.  By default, the server will search for these two files
in `certs/`.  This can be changed directly in the code by editing `CERTFILE`
and `KEYFILE` global variables.

```
$ python3 https_server.py -h

usage: https_server.py [-h] [--debug]

optional arguments:
  -h, --help  show this help message and exit
  --debug     Turn on debug logging
```

To actually run the server:
```
python3 https_server.py
```

This will start the server on `localhost:4443` by default.  You can visit
`https://localhost:4443` on your browser.  Make sure you inlcude `https` in
front of the domain, or the browser will not connect properly. To change the
host/port, go into the code and edit the `HOST` and `PORT` global variables.

By visiting the address, you should see a webpage with your
browser's JA3 fingerprint, browser name, and browser version.  It extracts all
of this data, except for the JA3 fingerprint, from the User-Agent string your
browser sends with the initial GET request.

