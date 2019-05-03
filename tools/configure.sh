# Postfix automatic configuration tool

REPOURL="https://raw.githubusercontent.com/coderboy14/digitalocean-email-docker/master/"
LETSENCRYPT_ROOT="/etc/letsencrypt/archive/${FDQN}/"
CERTIFICATE='/etc/ssl/certs/dovecot.pem'
CERTIFICATE_KEY='/etc/ssl/private/dovecot.pem'

runSQL() {
    mysql --host "${DB_HOST}" --user "${DB_USER}" --password "${DB_PASSWORD}" \
    -e "${1}"
}

fetchDirrectory() {
    # ARG1: Dirrectory Name
    # ARG2: Dirrectory Output
    curl -s "${REPOURL}/${1}" | tar -xv --strip-components=1 -C $2 -
}

fetchFile() {
    # ARG1: File Name
    # ARG2: File Output
    curl -s "${REPOURL}/${1}.gz" | gunzip -c - > $2
}

if [ -f "${CERTIFICATE_KEY}" ]; then
    if ["${USE_SELF_SIGNED}"=="yes"]; then
        echo "[SSL] Generating self signed key..."
        openssl req -x509 -newkey rsa:4096 -keyout ${CERTIFICATE_KEY} -out ${CERTIFICATE} -days 365 -nodes
        echo "[SSL] Self signed key generated!"
    fi
    if ["${USE_LETSENCRYPT}"=="yes"]; then
        echo "[SSL] Starting LETSENCRYPT"
        /usr/local/bin/certbot-auto certonly --standalone -d ${FQDN}
        cp ${LETSENCRYPT_ROOT}/fullchain.pem ${CERTIFICATE}
        echo "[SSL][LETSENCRYPT] Transfering CERTIFICATE"
        cp ${LETSENCRYPT_ROOT}/privkey.pem ${CERTIFICATE_KEY}
        echo "[SSL][LETSENCRYPT] Transfering KEY"
        echo "[SSL] Key generated!"
    fi
fi

# If the main.cf doesn't exist, it must need configuring!
if [ -f "/etc/postfix/main.cf" ]; then
    echo "[Postfix] Fetching files..."

    fetchFile "files/postfix/dynamicmaps.cf" "/etc/postfix/dynamicmaps.cf"
    fetchFile "files/postfix/makedefs.out" "/etc/postfix/makedefs.out"
    fetchFile "files/postfix/master.cf" "/etc/postfix/master.cf"
    fetchFile "files/postfix/post-install" "/etc/postfix/post-install"
    fetchFile "files/postfix/postfix-files" "/etc/postfix/postfix-files"
    fetchFile "files/postfix/postfix-script" "/etc/postfix/postfix-script"
    mkdir -pv /etc/postfix/{dynamicmaps.cf.d,postfix-files.d,sasl}
    echo "[Postfix] Fetched files!"

    echo "[Postfix] Configuring postfix files..."
    echo "[Postfix] Configuring '/etc/postfix/main.cf'..."
    echo "" > /etc/postfix/main.cf # clear the file (just in case)
    echo 'smtpd_banner = $myhostname ESMTP $mail_name (Ubuntu)' >> /etc/postfix/main.cf
    echo 'biff = no' >> /etc/postfix/main.cf
    echo 'append_dot_mydomain = no' >> /etc/postfix/main.cf
    echo 'readme_directory = no' >> /etc/postfix/main.cf
    echo 'compatibility_level = 2' >> /etc/postfix/main.cf
    echo 'smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination' >> /etc/postfix/main.cf
    echo "myhostname = ${HOSTNAME}" >> /etc/postfix/main.cf
    echo 'alias_maps = hash:/etc/aliases' >> /etc/postfix/main.cf
    echo 'alias_database = hash:/etc/aliases' >> /etc/postfix/main.cf
    echo 'myorigin = /etc/mailname' >> /etc/postfix/main.cf
    echo 'mydestination = localhost ' >> /etc/postfix/main.cf
    echo 'relayhost = ' >> /etc/postfix/main.cf
    echo 'mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128' >> /etc/postfix/main.cf
    echo 'mailbox_size_limit = 0' >> /etc/postfix/main.cf
    echo 'recipient_delimiter = +' >> /etc/postfix/main.cf
    echo 'inet_interfaces = all' >> /etc/postfix/main.cf
    echo 'inet_protocols = all' >> /etc/postfix/main.cf
    echo 'smtpd_sasl_type = dovecot' >> /etc/postfix/main.cf
    echo 'smtpd_sasl_path = private/auth' >> /etc/postfix/main.cf
    echo 'smtpd_sasl_auth_enable = yes' >> /etc/postfix/main.cf
    echo 'smtpd_recipient_restrictions = permit_sasl_authenticated,permit_mynetworks,reject_unauth_destination' >> /etc/postfix/main.cf
    echo 'virtual_transport = lmtp:unix:private/dovecot-lmtp' >> /etc/postfix/main.cf
    echo 'virtual_mailbox_domains = mysql:/etc/postfix/mysql-virtual-mailbox-domains.cf' >> /etc/postfix/main.cf
    echo 'virtual_mailbox_maps = mysql:/etc/postfix/mysql-virtual-mailbox-maps.cf' >> /etc/postfix/main.cf
    echo 'virtual_alias_maps = mysql:/etc/postfix/mysql-virtual-alias-maps.cf' >> /etc/postfix/main.cf
    echo "[Postfix] Configuring SSL..."
    if [-f "/etc/ssl"]; then mkdir -pv /etc/ssl; fi
    echo "smtpd_tls_cert_file=${CERTIFICATE}" >> /etc/postfix/main.cf
    echo "smtpd_tls_key_file=${CERTIFICATE_KEY}" >> /etc/postfix/main.cf
    echo 'smtpd_use_tls=yes' >> /etc/postfix/main.cf
    echo 'smtpd_tls_auth_only = yes' >> /etc/postfix/main.cf
    echo "[Postfix] SSL configured! Place certificate at '${CERTIFICATE}', and place key at '${CERTIFICATE_KEY}'"
    touch /etc/postfix/mysql-virtual-mailbox-domains.cf
    echo "
    user = ${DB_MAIL_USERNAME}
    password = ${DB_MAIL_PASSWORD}
    hosts = ${DB_HOST}
    dbname = ${DB_NAME}
    query = SELECT 1 FROM virtual_domains WHERE name='%s'
    " > /etc/postfix/mysql-virtual-mailbox-domains.cf
    echo "
    user = ${DB_MAIL_USERNAME}
    password = ${DB_MAIL_PASSWORD}
    hosts = ${DB_HOST}
    dbname = ${DB_NAME}
    query = SELECT 1 FROM virtual_users WHERE email='%s'
    " > /etc/postfix/mysql-virtual-mailbox-maps.cf 
    echo "
    user = ${DB_MAIL_USERNAME}
    password = ${DB_MAIL_PASSWORD}
    hosts = ${DB_HOST}
    dbname = ${DB_NAME}
    query = SELECT destination FROM virtual_aliases WHERE source='%s'
    " > /etc/postfix/mysql-virtual-alias-maps.cf
fi

if [ "$(runSQL 'SHOW DATABASES' | grep ${DB_NAME})" == $DB_NAME  ]; then
    echo "[MySQL] Configuring SQL..."
    echo "[MySQL] Creating database..."
    sh -c "mysqladmin -p create ${DB_NAME}"
    echo "[MySQL] Creating user and granting permissions..."
    runSQL "GRANT SELECT ON ${DB_NAME}.* TO '${DB_MAIL_USERNAME}'@'127.0.0.1' IDENTIFIED BY '${DB_MAIL_PASSWORD}';"
    runSQL "FLUSH PRIVILEGES;"
    echo "[MySQL] Creating table ${DB_NAME}.virtual_domains"
    runSQL "CREATE TABLE `${DB_NAME}`.`virtual_domains` (
        `id`  INT NOT NULL AUTO_INCREMENT,
        `name` VARCHAR(50) NOT NULL,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;"
    echo "[MySQL] Creating table ${DB_NAME}.virtual_users"
    runSQL "CREATE TABLE `${DB_NAME}`.`virtual_users` (
        `id` INT NOT NULL AUTO_INCREMENT,
        `domain_id` INT NOT NULL,
        `password` VARCHAR(106) NOT NULL,
        `email` VARCHAR(120) NOT NULL,
        PRIMARY KEY (`id`),
        UNIQUE KEY `email` (`email`),
        FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;"
    echo "[MySQL] Creating table ${DB_NAME}.virtual_aliases"
    runSQL "CREATE TABLE `${DB_NAME}`.`virtual_aliases` (
        `id` INT NOT NULL AUTO_INCREMENT,
        `domain_id` INT NOT NULL,
        `source` varchar(100) NOT NULL,
        `destination` varchar(100) NOT NULL,
        PRIMARY KEY (`id`),
        FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;"
    echo "[MySQL] Adding domain ${DOMAIN} to domain list"
    runSQL "INSERT INTO `${DB_NAME}`.`virtual_domains` (`id` ,`name`) VALUES ('1', '${DOMAIN}')"
    POSTMASTER_ADDR="postmaster@${DOMAIN}"
    POSTMASTER_PASSWORD="$(sh -c 'head /dev/urandom | tr -dc A-Za-z0-9 | head -c 13')"
    echo "[MySQL] Generating email '${POSTMASTER_ADDR}'..."
    runSQL "INSERT INTO `servermail`.`virtual_users` (`domain_id`, `password` , `email`)
        VALUES (
            ('1', ENCRYPT('${POSTMASTER_PASSWORD}', CONCAT('$6$', SUBSTRING(SHA(RAND()), -16))), '${POSTMASTER_ADDR}')
        );"
    echo "[MySQL] The password for '${POSTMASTER_ADDR}' is \"${POSTMASTER_PASSWORD}\"   It's recomended you change this soon!"
fi

if [ -f "/etc/dovecot/dovecot.conf" ]; then
    echo "[Dovecot] Configuring Dovecot..."

    echo "[Dovecot] Downloading files"

    fetchFile "files/dovecot/dovecot.conf" "/etc/dovecot/dovecot.conf"
    fetchDirrectory "files/dovecot/conf.d.tar.gz" "/etc/dovecot/conf.d"
    mkdir -p /etc/dovecot/private

    sh -c "mkdir -p /var/mail/vhosts/${DOMAIN}"

    USERNOTEXISTS=$(id -u vmail > /dev/null 2>&1; echo $?) 
    if [$USERNOTEXISTS == 1]; then
        echo "Creating system user 'vmail' with group 'vmail'..."
        groupadd -g 5000 vmail 
        useradd -g vmail -u 5000 vmail -d /var/mail
    fi

    chown -R vmail:vmail /var/mail

    if [ -f "/etc/dovecot/dovecot-sql.conf.ext" ]; then
        echo "driver = mysql" > /etc/dovecot/dovecot-sql.conf.ext
        echo "connect = host=${DB_HOST} dbname=${DB_NAME} user=${DB_MAIL_USERNAME} password=${DB_MAIL_PASSWORD}" >> /etc/dovecot/dovecot-sql.conf.ext
        echo "default_pass_scheme = SHA512-CRYPT" >> /etc/dovecot/dovecot-sql.conf.ext
        echo "password_query = SELECT email as user, password FROM virtual_users WHERE email='%u';" >> /etc/dovecot/dovecot-sql.conf.ext
    fi

    if [ -f "/etc/dovecot/conf.d/10-ssl.conf" ]; then
        echo "ssl = required" > /etc/dovecot/conf.d/10-ssl.conf
        echo "ssl_cert = <${CERTIFICATE}" >> /etc/dovecot/conf.d/10-ssl.conf
        echo "ssl_key = <${CERTIFICATE_KEY}" >> /etc/dovecot/conf.d/10-ssl.conf
        echo "ssl_client_ca_dir = /etc/ssl/certs" >> /etc/dovecot/conf.d/10-ssl.conf
    fi

    chown -R vmail:dovecot /etc/dovecot
    chmod -R o-rwx /etc/dovecot 
fi

#echo "" >> /etc/dovecot/
#echo "" >> /etc/dovecot/
#echo "" >> /etc/dovecot/
#echo "" >> /etc/dovecot/
#echo "" >> /etc/dovecot/

echo "[AUTOCONFIG]  Configuration finished. Will now restart POSTFIX and DOVECOT. This may cause your Docker Container to stop. 
If you have volumes enabled properly, the system will not reconfigure upon next startup."

service postfix restart
service dovecot restart