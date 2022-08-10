#!/bin/bash
cd /data
sed -i s/BUILD_NUMBER/$CDS_VERSION/ graylog2-server/src/main/resources/cds.properties
mvn package -DskipTests
