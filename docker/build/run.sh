#!/bin/bash
cd /data
sed -i s/BUILD_NUMBER/$CDS_VERSION/ graylog2-server/src/main/resources/cds.properties
sed -i s/4.0.0-rc.2-DEV-OVHcloud/$CDS_VERSION/ graylog2-web-interface/package.json
mvn package -DskipTests
