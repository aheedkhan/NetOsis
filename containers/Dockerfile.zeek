FROM zeek/zeek:7.0

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends tcpdump \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /site /zeek/logs

COPY sensor/zeek/ /site/
RUN chmod +x /site/entrypoint.sh

WORKDIR /zeek/logs
ENTRYPOINT ["/site/entrypoint.sh"]
