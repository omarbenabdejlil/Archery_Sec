FROM python:3.9-alpine3.19

LABEL MAINTAINER="Anand Tiwari"

ENV DJANGO_SETTINGS_MODULE=archerysecurity.settings.development

# Set archerysec as a work directory.
WORKDIR /home/archerysec/app
# Copy all file to archerysec folder.
COPY . .

ADD ./docker-files/init.sh /home/archerysec/app/init.sh

RUN echo "https://dl-cdn.alpinelinux.org/alpine/v3.19/main/" >> /etc/apk/repositories &&\
    apk add --update --no-cache bash netcat-openbsd && \
    adduser -h  /home/archerysec/app -s /bin/bash archerysec -D archerysec && \
    rm -rf /var/cache/apk/* && \
    chown archerysec /home/archerysec/app && \
    chgrp archerysec /home/archerysec/app && \
    chown -R archerysec:archerysec /home/archerysec/app && \
    chmod +x /home/archerysec/app/init.sh

RUN apk add --update --no-cache --virtual .build-deps \
    g++ \
    python3-dev \
    libxml2 \
    bash \
    libxml2-dev && \
    apk add libxslt-dev && \
    apk del .build-deps

RUN apk add --no-cache --virtual .build-deps \
    ca-certificates gcc postgresql-dev linux-headers musl-dev \
    libffi-dev jpeg-dev zlib-dev \
    postgresql-client \
    git \
    libmagic


RUN pip install --upgrade pip wheel &&\
    pip install --no-cache-dir --use-deprecated=legacy-resolver -r requirements.txt

USER archerysec

EXPOSE 8000

CMD ["/home/archerysec/app/init.sh"]
