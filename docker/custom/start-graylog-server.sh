#!/bin/bash

source /etc/default/graylog-server 
#file=$(grep http_tls_cert_file /etc/graylog/server/server.conf |awk -F ' = ' '{print $2}')
#if [ -n "$file" ] ; then
#  if [ -f "$file" ] ; then
#    $JAVA_HOME/bin/keytool -importcert -storepass changeit -keystore -cacerts -noprompt -trustcacerts -alias graylog-self-signed -file "$file"
#    $JAVA_HOME/bin/keytool -importcert -storepass changeit -keystore /etc/ssl/certs/graylog/cacerts.jks -noprompt -trustcacerts -alias graylog-self-signed -file "$file"
#  fi
#fi

#if [ -d "/usr/share/graylog-server/plugin.bak" ] ; then
#    cp -ar /usr/share/graylog-server/plugin.bak/* /usr/share/graylog-server/plugin/
#fi
if [ -f "/etc/graylog/server/maintenance" ] ; then
    exit 1
fi

exec $GRAYLOG_COMMAND_WRAPPER ${JAVA:=/usr/bin/java} $GRAYLOG_SERVER_JAVA_OPTS $GRAYLOG_SERVER_JAVA_EXTRA_OPTS \
    -Dlog4j.configurationFile=file:///etc/graylog/server/log4j.xml \
    -Djava.library.path=/usr/share/graylog-server/lib/sigar \
    -jar /usr/share/graylog-server/graylog.jar server -f /etc/graylog/server/server.conf -np \
    $GRAYLOG_SERVER_ARGS
