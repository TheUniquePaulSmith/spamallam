FROM alpine:3.20

RUN apk add --no-cache postfix postfix-pcre gettext openssl ca-certificates tzdata

COPY templates/ /etc/postfix/templates/
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

# 2525 inbound SMTP, 2587 STARTTLS-enforced inbound, 10025 internal re-injection
EXPOSE 2525 2587 10025

ENTRYPOINT ["/entrypoint.sh"]
