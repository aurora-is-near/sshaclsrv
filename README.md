# sshaclsrv

A minimal implementation for a role-based key distribution framework for OpenSSH (node-side).

sshaclsrv utilises OpenSSH's AuthorizedKeysCommand to look up authorized keys
remotely, with local fallback.

Keys can be matched to the hostname with patterns, and keys can also carry an expiration time.

sshaclsrv is used as AuthorizedKeysCommand and parses a keyfile
containing:

  - Hostname on which the key is valid (can contain \* for
matching). 
  - SystemUser as which to authenticate. 
  - The SHA256 hash of
the user/node that is connecting. 
  - ExpireTime, optional.
YYYYMMDDHHmmSS. 
  - AuthorizedKeys entry to return on match, which must
contain the key and can contain additional options for sshd.

Remote key repositories are standard HTTP file servers, using the URL to
match the keys. Urls have the format:

```http(s)://fqdn/path/sshfingerprint/hostname/systemuser```

Returned entries are one key per line. Remote entries require a signature that is created by delegatesign.
Delegated signatures allow delegating authority for a limited time to a third party, without having
to update the on-node configuration of sshaclsrv.

If a remote lookup fails (404 not found) or times out (5 seconds), the local file will be consulted.

OpenSSH config:

/etc/ssh/sshd_config

    Match Group aclusers
        AuthorizedKeysFile /etc/ssh/empty
        AuthorizedKeysCommand /usr/local/libexec/sshacl/sshaclsrv /etc/ssh/acl.cfg %u %f
        AuthorizedKeysCommandUser sshacl

To add to system:

    $ groupadd aclusers
    $ usermod -a -G aclusers <systemuser to manage>

Correctly updating the keyfile:

    $ mv new-keyfile keyfile 

### Security Note

Be aware that sshacl intentionally does *NOT* check the owner or
permission of the key-file. The security of your system will depend on
how this file can be modified.
