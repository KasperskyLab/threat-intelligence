# The base image
FROM python:3.11-alpine as base

###########################################################
#                       Building
###########################################################
FROM base as builder

# Working directory
WORKDIR /builder

# Install system dependencies
RUN apk update && \
    apk --no-cache add build-base git libxml2-dev libxslt-dev && \
    rm -rf /var/cache/apk/*

# Initialize the virtual environment
RUN python -m venv /venv && \
    /venv/bin/pip install --upgrade pip && \
    /venv/bin/pip install wheel

# Install dependencies
COPY src/requirements.txt ./
RUN /venv/bin/pip install --no-cache-dir -r ./requirements.txt

###########################################################
#                      Connector
###########################################################
FROM base

# Working directory
WORKDIR /app

# Copy sources of the connector
COPY src/kaspersky /app/kaspersky
COPY src/main.py /app/main.py

# Install system dependencies
RUN apk update && \
    apk --no-cache add libmagic && \
    rm -rf /var/cache/apk/*

# Copy the virtual environment
COPY --from=builder /venv /app/.venv

# Entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
CMD [ "/entrypoint.sh" ]
ENTRYPOINT [ "/bin/sh" ]
