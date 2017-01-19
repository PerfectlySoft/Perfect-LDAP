tar czvf /tmp/ldap.tgz Sources Tests Package.swift
scp /tmp/ldap.tgz 192.168.56.11:/tmp
ssh 192.168.56.11 "cd /tmp;rm -rf ldap;mkdir ldap;cd ldap;tar xzvf ../ldap.tgz;swift build;swift test"
