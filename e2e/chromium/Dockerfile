FROM debian:bookworm-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      --no-install-recommends \
      chromium ca-certificates util-linux fonts-liberation \
      && rm -rf /var/lib/apt/lists/* \
      && groupadd -g 1000 sandbox \
      && useradd -u 1000 -g 1000 -m -s /bin/sh sandbox \
      && mkdir -p /sandbox \
      && chown sandbox:sandbox /sandbox

COPY --chmod=0555 verify-sandbox.sh /usr/local/bin/verify-sandbox

USER sandbox:sandbox
WORKDIR /sandbox
ENV HOME=/sandbox
CMD ["sleep", "infinity"]
