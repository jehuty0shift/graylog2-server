#!/bin/bash
cd /data/plugin
echo "About to deploy plugin"
mvn clean deploy -s /root/.m2/settings-artifactory.xml 2>&1 | tee log2.txt
echo "Plugin might be deployed"
ls -lh target/
