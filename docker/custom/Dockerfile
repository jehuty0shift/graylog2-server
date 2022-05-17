FROM   ldp-default-docker.artifactory.ovhcloud.tools/ldp-openzulu-dk-17
ENV     DEBIAN_FRONTEND=noninteractive \
        GRAYLOG_VERSION=4.0.0 \
        GRAYLOG_MAJOR=4.0 \
        REVISION=202205162005

COPY    ["graylog.tar.gz", "graylog-server", "CA-logs.ovh.com.crt", "ldap-ldp.crt", "/tmp/"]
ADD     plugins /tmp/plugins/
COPY    start-graylog-server.sh /usr/bin/start-graylog-server.sh

RUN     apt-get update && \
        apt-get install --no-install-recommends ca-certificates && \
        cp /tmp/CA-logs.ovh.com.crt /usr/local/share/ca-certificates/CA-logs.ovh.com.pem && \
        cp /tmp/ldap-ldp.crt /usr/local/share/ca-certificates/CA-ldap.logs.ovh.com.pem && \
        ln -s /usr/local/share/ca-certificates/CA-logs.ovh.com.pem /usr/local/share/ca-certificates/CA-logs.ovh.com.crt && \
        ln -s /usr/local/share/ca-certificates/CA-ldap.logs.ovh.com.pem /usr/local/share/ca-certificates/CA-ldap.logs.ovh.com.crt && \
        update-ca-certificates && \
        cd /etc/ssl/certs && \
        if [ -d "$JAVA_HOME/jre/lib/security" ] ; then export JAVA_SECURITY="$JAVA_HOME/jre/lib/security"; else export JAVA_SECURITY="$JAVA_HOME/lib/security" ; fi && \
        cd /tmp && \
        cp /tmp/CA-logs.ovh.com.crt $JAVA_SECURITY/CA-logs.ovh.com.crt && \
        cp /tmp/ldap-ldp.crt $JAVA_SECURITY/CA-ldap.logs.ovh.com.crt && \
        $JAVA_HOME/bin/keytool -importcert -storepass changeit -keystore $JAVA_SECURITY/cacerts -noprompt -trustcacerts -alias logsovhcom -file $JAVA_SECURITY/CA-logs.ovh.com.crt && \
        $JAVA_HOME/bin/keytool -importcert -storepass changeit -keystore -cacerts -noprompt -trustcacerts -alias logsovhcom -file $JAVA_SECURITY/CA-logs.ovh.com.crt && \
        $JAVA_HOME/bin/keytool -importcert -storepass changeit -keystore $JAVA_SECURITY/cacerts -noprompt -trustcacerts -alias ldaplogsovhcom -file $JAVA_SECURITY/CA-ldap.logs.ovh.com.crt && \
        $JAVA_HOME/bin/keytool -importcert -storepass changeit -keystore -cacerts -noprompt -trustcacerts -alias ldaplogsovhcom -file $JAVA_SECURITY/CA-ldap.logs.ovh.com.crt && \
        mkdir -p /etc/ssl/certs/graylog && \
        cp $JAVA_SECURITY/cacerts /etc/ssl/certs/graylog/cacerts.jks && \
	apt-get install -qqy wget ntp ntpdate apt-transport-https uuid-runtime && \
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
        chmod +x /usr/bin/start-graylog-server.sh && \
        mv /tmp/graylog-server /etc/default/graylog-server && \
        chown ldp:ldp /usr/bin/start-graylog-server.sh /etc/default/graylog-server

EXPOSE  12900 9000 12201 12202/udp 12203 12204 5140

RUN     cd /tmp && \
        mkdir /tmp/graylog && \
        tar -xvzf graylog.tar.gz -C /tmp/graylog && \
        cd graylog && \
        rm -rf /usr/share/graylog-server/* && \
        mv * /usr/share/graylog-server/ && \
        chown ldp:ldp /usr/share/graylog-server && \
        rmdir /tmp/graylog && rm -f /tmp/graylog.tar.gz && \
        mkdir -p /usr/share/graylog-server/plugin && \
        mv /tmp/plugins/* /usr/share/graylog-server/plugin && \
        chown -R ldp:ldp /usr/share/graylog-server/plugin

RUN set -ex && for path in /etc/graylog/server /var/log/graylog-server ; do \
      mkdir -p "$path"; \
      chown -R ldp:ldp "$path"; \
    done ; \
    chown ldp:ldp /usr/bin/start-graylog-server.sh && \
    rm -rf /tmp/* /var/tmp/*

USER ldp

VOLUME ["/etc/graylog/server", "/usr/share/graylog-server/plugin", "/var/log/graylog-server"]

WORKDIR /etc/graylog/server

ENV GRAY_HEAP_SIZE 30g

ENTRYPOINT ["/usr/bin/start-graylog-server.sh"]
