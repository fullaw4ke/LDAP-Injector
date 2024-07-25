
# LDAP Injection Script

This C++ program performs LDAP injection testing against a specified URL, attempting to exploit potential vulnerabilities in LDAP query handling. It systematically tests combinations of alphanumeric characters and symbols to uncover sensitive information or gain unauthorized access. The tool utilizes libcurl for making HTTP requests and includes signal handling for graceful termination. Useful for security professionals and developers to assess LDAP query security in web applications.

# Installing dependencies

```bash
sudo apt-get update
```

```bash
sudo apt-get install libcurl4-openssl-dev libargparse-dev
```
# Compile

```bash
g++ ldap-injector.c++ -o injector -I. -lcurl
```

# Usage
```bash
./injector -u "http://internal.analysis.htb/users/list.php?name"
```
