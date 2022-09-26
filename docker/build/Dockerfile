FROM ldp-default-docker.artifactory.ovhcloud.tools/ldp-maven-dk-17

RUN apt-get update && apt-get install bzip2

COPY run.sh /run.sh
RUN chmod +x /run.sh

CMD ["/run.sh"]
