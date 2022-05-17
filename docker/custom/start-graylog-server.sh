#!/bin/bash

source /etc/default/graylog-server 
#file=$(grep http_tls_cert_file /etc/graylog/server/server.conf |awk -F ' = ' '{print $2}')
#if [ -n "$file" ] ; then
#  if [ -f "$file" ] ; then
#    $JAVA_HOME/bin/keytool -importcert -storepass changeit -cacerts -noprompt -trustcacerts -alias graylog-self-signed -file "$file"
#    $JAVA_HOME/bin/keytool -importcert -storepass changeit -keystore /etc/ssl/certs/graylog/cacerts.jks -noprompt -trustcacerts -alias graylog-self-signed -file "$file"
#  fi
#fi

file_chain="/etc/graylog/server/cluster.chain"
if [ -f "${file_chain}" ] ; then
  if [ -w "$JAVA_SECURITY/cacerts" ] ; then
    $JAVA_HOME/bin/keytool -importcert -storepass changeit -cacerts -noprompt -trustcacerts -alias cluster-self-signed -file "${file_chain}"
  fi
  $JAVA_HOME/bin/keytool -importcert -storepass changeit -keystore /etc/ssl/certs/graylog/cacerts.jks -noprompt -trustcacerts -alias cluster-self-signed -file "${file_chain}"
fi

#if [ -d "/usr/share/graylog-server/plugin.bak" ] ; then
#    cp -ar /usr/share/graylog-server/plugin.bak/* /usr/share/graylog-server/plugin/
#fi
if [ -f "/etc/graylog/server/maintenance" ] ; then
    echo "find maintenance file, prevent starting graylog!"
    sleep 30
    exit 2
fi

file_jmx_config="/etc/graylog/server/config.yaml"
if [ -f "${file_jmx_config}" ]; then
    GRAYLOG_SERVER_JAVA_OPTS="$GRAYLOG_SERVER_JAVA_OPTS -javaagent:/opt/jmx_exporter/jmx_prometheus_javaagent.jar=9101:/etc/graylog/server/config.yaml"
fi


exec $GRAYLOG_COMMAND_WRAPPER ${JAVA:=/usr/bin/java} $GRAYLOG_SERVER_JAVA_OPTS $GRAYLOG_SERVER_JAVA_EXTRA_OPTS \
    -Dlog4j.configurationFile=file:///etc/graylog/server/log4j.xml \
    -Djava.library.path=/usr/share/graylog-server/lib/sigar \
    -jar /usr/share/graylog-server/graylog.jar server -f /etc/graylog/server/server.conf -np \
    $GRAYLOG_SERVER_ARGS

