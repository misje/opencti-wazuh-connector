FROM python:3.11-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

#COPY src /opt/opencti-connector-wazuh
COPY src/requirements.txt /opt/opencti-connector-wazuh/
RUN apk --no-cache add git build-base libmagic libffi-dev && \
   cd /opt/opencti-connector-wazuh && \
   pip3 install --no-cache-dir -r requirements.txt && \
   apk del git build-base

COPY src /opt/opencti-connector-wazuh
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
