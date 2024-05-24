FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

LABEL org.opencontainers.image.documentation="https://misje.github.io/opencti-wazuh-connector"
LABEL org.opencontainers.image.licenses="Apache 2.0"
LABEL org.opencontainers.image.version="dev"
LABEL org.opencontainers.image.source="https://github.com/misje/opencti-wazuh-connector"

COPY src/requirements.txt /opt/opencti-connector-wazuh/
WORKDIR /opt/opencti-connector-wazuh
RUN apk --no-cache add build-base libmagic && \
   pip3 install --no-cache-dir -r requirements.txt && \
   apk del build-base
RUN pip3 install --no-cache-dir -r requirements.txt
COPY src /opt/opencti-connector-wazuh
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh && \
   mkdir -p /var/cache/wazuh
ENTRYPOINT ["/entrypoint.sh"]
