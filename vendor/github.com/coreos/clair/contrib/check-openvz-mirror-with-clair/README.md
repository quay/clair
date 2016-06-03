check_openvz_mirror_with_clair
==============================

**check_openvz_mirror_with_clair** - little tool for add templates from OpenVZ 6 mirror to [clair](https://github.com/coreos/clair) for vulnerability analysis it.

Install
-------

You must have already install and worked [clair](https://github.com/coreos/clair)

```
export GOPATH=$(pwd)
go get github.com/coreos/clair/contrib/check-openvz-mirror-with-clair
go build github.com/coreos/clair/contrib/check-openvz-mirror-with-clair
```

Usage
-----

```
check_openvz_mirror_with_clair -m MIRROR [ -i ADRESS -p PORT -P PRIORITY --help ]
```

- -m  - link for openvz mirror like https://download.openvz.org/template/precreated/ or path to local mirror with listing file like /home/user/openvzmirror
- -a  - adress to clair API
- -p  - port to clair API
- -P  - the minimum priority of the returned vulnerabilities (default "High")
- -cert  - a PEM encoded certificate file for connect to clair
- -key - a PEM encoded private key file for connect to clair
- -CA - a PEM eoncoded CA's certificate file for connet to clair

Example
--------
```
# Local mirror and clair with  client certificate auth
./check_openvz_mirror_with_clair -m /home/user/Downloads/mirror --cert /home/user/clair/cert/client1.crt --key /home/user/clair/cert/client1.key.insecure --CA /home/user/clair/cert/ca.crt -P LOW
We use:
Clair -  127.0.0.1:6060
We have clair with APIVersion: 1 and EngineVersion: 1
OpenVZ mirror -  /home/user/Downloads/mirror
We have 2 templates on mirror

Try to add  debian-6.0-x86_64-someimage
debian-6.0-x86_64-someimage added success
You can check it via:
curl -s https://127.0.0.1:6060/v1/layers/debian-6.0-x86_64-someimage/vulnerabilities?minimumPriority=Low --cert /home/user/clair/cert/client1.crt --key /home/user/clair/cert/client1.key.insecure --cacert /home/user/clair/cert/ca.crt | python -m json.tool
Detect 169 vulnerabilities for this template

Try to add  debian-7.0-x86_64-someimage
debian-7.0-x86_64-someimage added success
You can check it via:
curl -s https://127.0.0.1:6060/v1/layers/debian-7.0-x86_64-someimage/vulnerabilities?minimumPriority=Low --cert /home/user/clair/cert/client1.crt --key /home/user/clair/cert/client1.key.insecure --cacert /home/user/clair/cert/ca.crt | python -m json.tool
Detect 146 vulnerabilities for this template


# Remote mirror 
./check_openvz_mirror_with_clair -m http://mirror.yandex.ru/mirrors/download.openvz.org/template/precreated/ -a 127.0.0.1 -p 6060 -P Low
We use:
Clair -  127.0.0.1:6060
OpenVZ mirror -  http://mirror.yandex.ru/mirrors/download.openvz.org/template/precreated/
We have 45 templates on mirror

Try to add  centos-5-x86_64-devel
centos-5-x86_64-devel added success
You can check it via:
curl -s http://127.0.0.1:6060/v1/layers/centos-5-x86_64-devel/vulnerabilities?minimumPriority=Low | python -m json.tool
Detect 0 vulnerabilities for this template

Try to add  centos-5-x86_64
centos-5-x86_64 added success
You can check it via:
curl -s http://127.0.0.1:6060/v1/layers/centos-5-x86_64/vulnerabilities?minimumPriority=Low | python -m json.tool
Detect 0 vulnerabilities for this template

Try to add  centos-5-x86-devel
centos-5-x86-devel added success
You can check it via:
curl -s http://127.0.0.1:6060/v1/layers/centos-5-x86-devel/vulnerabilities?minimumPriority=Low | python -m json.tool
Detect 0 vulnerabilities for this template

Try to add  centos-5-x86
centos-5-x86 added success
You can check it via:
curl -s http://127.0.0.1:6060/v1/layers/centos-5-x86/vulnerabilities?minimumPriority=Low | python -m json.tool
Detect 0 vulnerabilities for this template

Try to add  centos-6-x86_64-devel
centos-6-x86_64-devel added success
You can check it via:
curl -s http://127.0.0.1:6060/v1/layers/centos-6-x86_64-devel/vulnerabilities?minimumPriority=Low | python -m json.tool
Detect 3 vulnerabilities for this template

Try to add  centos-6-x86_64-minimal
centos-6-x86_64-minimal added success
You can check it via:
curl -s http://127.0.0.1:6060/v1/layers/centos-6-x86_64-minimal/vulnerabilities?minimumPriority=Low | python -m json.tool
Detect 1 vulnerabilities for this template

Try to add  centos-6-x86_64
centos-6-x86_64 added success
You can check it via:
curl -s http://127.0.0.1:6060/v1/layers/centos-6-x86_64/vulnerabilities?minimumPriority=Low | python -m json.tool
Detect 2 vulnerabilities for this template

Try to add  centos-6-x86-devel
centos-6-x86-devel added success
You can check it via:
curl -s http://127.0.0.1:6060/v1/layers/centos-6-x86-devel/vulnerabilities?minimumPriority=Low | python -m json.tool
Detect 3 vulnerabilities for this template
...

```

