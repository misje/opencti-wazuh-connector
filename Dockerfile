FROM python:3.12-alpine AS build
ARG PYCTI_VERSION="6.2.7" # NOTE: If building locally, replace/update this!
WORKDIR /app

RUN apk --no-cache add build-base
COPY src/requirements.txt .
RUN sed -ri "s/__PYCTI_VERSION__/${PYCTI_VERSION}/" requirements.txt && \
   pip3 wheel --no-cache-dir --no-deps --wheel-dir /app/wheels -r requirements.txt


FROM python:3.12-alpine
ARG CONNECTOR_VERSION="0.3.0" # NOTE: If building locally, replace/update this!
WORKDIR /app
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

LABEL org.opencontainers.image.description="Wazuh OpenCTI enrichment connector"
LABEL org.opencontainers.image.documentation="https://misje.github.io/opencti-wazuh-connector"
LABEL org.opencontainers.image.licenses="Apache 2.0"
LABEL org.opencontainers.image.source="https://github.com/misje/opencti-wazuh-connector"

RUN apk --no-cache add libmagic
COPY --from=build /app/wheels /wheels
COPY --from=build /app/requirements.txt .
RUN pip3 install --no-cache-dir /wheels/*
COPY src .
RUN sed -ri "s/__CONNECTOR_VERSION__/${CONNECTOR_VERSION}/" wazuh/wazuh.py
ENTRYPOINT ["python3", "main.py"]
