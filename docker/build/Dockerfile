FROM ldp-default-docker.artifactory.ovhcloud.tools/ldp-maven-dk-17

ARG CDS_VERSION
ENV CDS_VERSION=$CDS_VERSION

COPY gl /data

RUN cd /data && \
    sed -i s/BUILD_NUMBER/$CDS_VERSION/ graylog2-server/src/main/resources/cds.properties && \
    sed -i s/4.0.0-rc.2-DEV-OVHcloud/${CDS_VERSION}-OVHcloud/ graylog2-web-interface/package.json && \
    mvn package -DskipTests && \
    tar czf graylog2-server-build.tar.gz * && \
    mv graylog2-server-build.tar.gz ../ && \
    tar -xzf target/assembly/graylog*.tar.gz graylog.jar && \
    mkdir libGraylog && \
    mv graylog.jar libGraylog && \
    mv $JAVA_HOME ./jdk17 && \
    tar czf target.tar.gz graylog2-server/target/ graylog-storage-elasticsearch6/target/ graylog-storage-elasticsearch7/target/ graylog-storage-opensearch2/target/ jdk17/ libGraylog/ && \
    mv target.tar.gz ../  && \
    rm -rf * ..\ && \
    mv ../*tar.gz . && \
    rm ~/.m2/repository -rf

COPY run.sh /run.sh
RUN chmod +x /run.sh

CMD ["/run.sh"]
