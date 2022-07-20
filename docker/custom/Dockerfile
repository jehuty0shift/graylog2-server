FROM   ldp-default-docker.artifactory.ovhcloud.tools/ldp-openzulu-dk-21
ENV     DEBIAN_FRONTEND=noninteractive \
        GRAYLOG_VERSION=4.0.0 \
        GRAYLOG_MAJOR=4.0 \
        REVISION=202309271705

COPY    ["graylog.tar.gz", "graylog-server", "CA-logs.ovh.com.crt", "ldap-ldp.crt", "old-ldap-ldp.crt", "mongo-CA.crt", "/tmp/"]
ADD     plugins /tmp/plugins/
COPY    start-graylog-server.sh /usr/bin/start-graylog-server.sh

RUN     apt-get update && \
        apt-get install -qqy --no-install-recommends ca-certificates wget ntp ntpdate apt-transport-https uuid-runtime && \
        cp /tmp/CA-logs.ovh.com.crt /usr/local/share/ca-certificates/CA-logs.ovh.com.pem && \
        cp /tmp/ldap-ldp.crt /usr/local/share/ca-certificates/CA-ldap.logs.ovh.com.pem && \
        cp /tmp/old-ldap-ldp.crt /usr/local/share/ca-certificates/CA-old-ldap.logs.ovh.com.pem && \
        ln -s /usr/local/share/ca-certificates/CA-logs.ovh.com.pem /usr/local/share/ca-certificates/CA-logs.ovh.com.crt && \
        ln -s /usr/local/share/ca-certificates/CA-ldap.logs.ovh.com.pem /usr/local/share/ca-certificates/CA-ldap.logs.ovh.com.crt && \
        ln -s /usr/local/share/ca-certificates/CA-old-ldap.logs.ovh.com.pem /usr/local/share/ca-certificates/CA-old-ldap.logs.ovh.com.crt && \
        update-ca-certificates && \
        cd /etc/ssl/certs && \
        if [ -d "$JAVA_HOME/jre/lib/security" ] ; then export JAVA_SECURITY="$JAVA_HOME/jre/lib/security"; else export JAVA_SECURITY="$JAVA_HOME/lib/security" ; fi && \
        cd /tmp && \
        cp /tmp/CA-logs.ovh.com.crt $JAVA_SECURITY/CA-logs.ovh.com.crt && \
        cp /tmp/ldap-ldp.crt $JAVA_SECURITY/CA-ldap.logs.ovh.com.crt && \
        cp /tmp/old-ldap-ldp.crt $JAVA_SECURITY/CA-old-ldap.logs.ovh.com.crt && \
        cp /tmp/mongo-CA.crt $JAVA_SECURITY/CA-mongoDB.crt && \
        $JAVA_HOME/bin/keytool -importcert -storepass changeit -keystore $JAVA_SECURITY/cacerts -noprompt -trustcacerts -alias logsovhcom -file $JAVA_SECURITY/CA-logs.ovh.com.crt && \
        $JAVA_HOME/bin/keytool -importcert -storepass changeit -keystore -cacerts -noprompt -trustcacerts -alias logsovhcom -file $JAVA_SECURITY/CA-logs.ovh.com.crt && \
        $JAVA_HOME/bin/keytool -importcert -storepass changeit -keystore $JAVA_SECURITY/cacerts -noprompt -trustcacerts -alias ldaplogsovhcom -file $JAVA_SECURITY/CA-ldap.logs.ovh.com.crt && \
        $JAVA_HOME/bin/keytool -importcert -storepass changeit -keystore -cacerts -noprompt -trustcacerts -alias ldaplogsovhcom -file $JAVA_SECURITY/CA-ldap.logs.ovh.com.crt && \
        $JAVA_HOME/bin/keytool -importcert -storepass changeit -keystore $JAVA_SECURITY/cacerts -noprompt -trustcacerts -alias oldldaplogsovhcom -file $JAVA_SECURITY/CA-old-ldap.logs.ovh.com.crt && \
        $JAVA_HOME/bin/keytool -importcert -storepass changeit -keystore -cacerts -noprompt -trustcacerts -alias oldldaplogsovhcom -file $JAVA_SECURITY/CA-old-ldap.logs.ovh.com.crt && \
        $JAVA_HOME/bin/keytool -importcert -storepass changeit -keystore $JAVA_SECURITY/cacerts -noprompt -trustcacerts -alias mongologsovhcom -file $JAVA_SECURITY/CA-mongoDB.crt && \
        $JAVA_HOME/bin/keytool -importcert -storepass changeit -keystore -cacerts -noprompt -trustcacerts -alias mongologsovhcom -file $JAVA_SECURITY/CA-mongoDB.crt && \
        mkdir -p /etc/ssl/certs/graylog && \
        cp $JAVA_SECURITY/cacerts /etc/ssl/certs/graylog/cacerts.jks && \
        echo "server ntp.ovh.net" > /etc/ntp.conf && \
        wget https://packages.graylog2.org/repo/packages/graylog-${GRAYLOG_MAJOR}-repository_latest.deb && \
        dpkg -i --force-confold graylog-${GRAYLOG_MAJOR}-repository_latest.deb && \
        apt-get update && apt-get install graylog-server && \
        apt-get clean && rm -rf /var/lib/apt/lists/* && \
        chown -R ldp:ldp /usr/share/graylog-server /etc/ssl/certs/graylog && \
        set -ex && for path in /etc/graylog/server /usr/share/graylog-server/plugin /var/log/graylog-server ; do \
            mkdir -p "$path"; \
            chown -R ldp:ldp "$path"; \
        done ; \
        rm -rf /usr/share/graylog-server/* && \
        mv /tmp/graylog-server /etc/default/graylog-server && \
        chown -R ldp:ldp /etc/default/graylog-server

RUN     cd /tmp && \
        mkdir /tmp/graylog && \
        tar -xvzf graylog.tar.gz -C /tmp/graylog && \
        cd /tmp/graylog && \
        mkdir -p /usr/share/graylog-server && \
        mv * /usr/share/graylog-server/ && \
        find /usr/share/graylog-server ! -user ldp -exec chown ldp:ldp {} \; ; \
        ls -altr /usr/share/graylog-server ; \
        rmdir /tmp/graylog ; \
        rm -f /tmp/graylog.tar.gz && \
        mkdir -p /usr/share/graylog-server/plugin && \
        mv /tmp/plugins/* /usr/share/graylog-server/plugin && \
        find /usr/share/graylog-server/plugin ! -user ldp -exec chown ldp:ldp {} \; ; \
        rmdir /tmp/plugins ; \
        rm -rf /tmp/* /var/tmp/* ; \
        set -ex && for path in /etc/graylog/server /var/log/graylog-server ; do \
          mkdir -p "$path"; \
          chown -R ldp:ldp "$path"; \
        done ; \
        chmod +x /usr/bin/start-graylog-server.sh && \
        chown ldp:ldp /usr/bin/start-graylog-server.sh

EXPOSE  12900 9000 12201 12202/udp 12203 12204 5140

USER ldp

VOLUME ["/etc/graylog/server", "/var/log/graylog-server"]

WORKDIR /etc/graylog/server

ENV GRAY_HEAP_SIZE 30g

ENTRYPOINT ["/usr/bin/start-graylog-server.sh"]

