FROM rspamd/rspamd:latest

USER root
RUN apt-get update && apt-get install -y --no-install-recommends gettext-base \
    && rm -rf /var/lib/apt/lists/*

COPY local.d/ /etc/rspamd/local.d/
COPY templates/ /etc/rspamd/templates/
COPY lua/rspamd.local.lua /etc/rspamd/rspamd.local.lua
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

EXPOSE 11333 11334

ENTRYPOINT ["/entrypoint.sh"]
