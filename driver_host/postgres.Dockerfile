FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40

RUN apk add --no-cache "postgresql18=18.4-r0" \
    && mkdir -p /var/lib/postgresql/18/docker /var/run/postgresql \
    && chown -R postgres:postgres /var/lib/postgresql /var/run/postgresql

COPY driver_host/postgres_entrypoint.sh /usr/local/bin/postgres-entrypoint.sh
RUN chmod 0755 /usr/local/bin/postgres-entrypoint.sh

USER 70:70
ENV PGDATA=/var/lib/postgresql/18/docker
ENTRYPOINT ["/usr/local/bin/postgres-entrypoint.sh"]
CMD ["postgres"]
