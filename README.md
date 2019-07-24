# docker-run-as
retrieve "docker run" from "docker inspect" of existing containers

example:
go run inspect.go

2019/02/08 15:33:57 output cmd:
 docker run \
	--name=owncloud \
	--hostname=1edab40175a8 \
	--user= \
	--env=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
	--env='PHPIZE_DEPS=autoconf 		dpkg-dev 		file 		g++ 	gcc 		libc-dev 		libpcre3-dev 		make 		pkg-config 	re2c' \
	--env=PHP_INI_DIR=/usr/local/etc/php \
	--env=APACHE_CONFDIR=/etc/apache2 \
	--env=APACHE_ENVVARS=/etc/apache2/envvars \
	--env=PHP_EXTRA_BUILD_DEPS=apache2-dev \
	--env=PHP_EXTRA_CONFIGURE_ARGS=--with-apxs2 \
	--env='PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2' \
	--env='PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2' \
	--env='PHP_LDFLAGS=-Wl,-O1 -Wl,--hash-style=both -pie' \
	--env='GPG_KEYS=1A4E8B7277C42E53DBA9C7B9BCAA30EA9C0D5763 6E4F6AB321FDC07F2C332E3AC2BF0BC433CFC8B3' \
	--env=PHP_VERSION=7.0.24 \
	--env=PHP_URL=https://secure.php.net/get/php-7.0.24.tar.xz/from/this/mirror \
	--env=PHP_ASC_URL=https://secure.php.net/get/php-7.0.24.tar.xz.asc/from/this/mirror \
	--env=PHP_SHA256=4dba7aa365193c9229f89f1975fad4c01135d29922a338ffb4a27e840d6f1c98 \
	--env=PHP_MD5= \
	--env=OWNCLOUD_VERSION=10.0.3 \
	--volume=/var/craash/containers/storage/owncloud/var/www/html:/var/www/html \
	--volume=/var/www/html \
	-p 192.168.4.77:8080:80 \
	--label CRaaSH="" \
	sha256:f5f5cc2704733cd3a606372a45a6c0da0d08e7236668bacdaa3adc6c93df09cf \
	apache2-foreground
