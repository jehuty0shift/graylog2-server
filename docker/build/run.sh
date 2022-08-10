#!/bin/bash
cd /data
sed -i s/$CDS_VERSION/BUILD_NUMBER/ graylog2-server/src/main/resources/cds.properties
mvn package -DskipTests
