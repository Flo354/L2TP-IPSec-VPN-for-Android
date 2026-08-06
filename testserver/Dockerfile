# ---------------------------------------------------------------------------
# Real L2TP/IPsec (PSK) lab server: strongSwan (starter/stroke) + xl2tpd + pppd
#
# Mirrors what an Orange Livebox Pro offers:
#   IKEv1 main mode, PSK, aes256-sha256-modp2048 / ESP aes256-sha256,
#   transport mode, no PFS, NAT-T forced on (ESP always in UDP/4500).
#
# TEST INFRASTRUCTURE ONLY - credentials are hard-coded on purpose.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        strongswan \
        strongswan-starter \
        strongswan-charon \
        libstrongswan-standard-plugins \
        libcharon-extra-plugins \
        xl2tpd \
        ppp \
        iproute2 \
        iptables \
        iputils-ping \
        tcpdump \
        procps \
        net-tools \
        kmod \
        less \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- IPsec / strongSwan -----------------------------------------------------
COPY conf/ipsec.conf        /etc/ipsec.conf
COPY conf/ipsec.secrets     /etc/ipsec.secrets
COPY conf/strongswan.conf   /etc/strongswan.conf

# --- L2TP -------------------------------------------------------------------
COPY conf/xl2tpd.conf       /etc/xl2tpd/xl2tpd.conf

# --- PPP --------------------------------------------------------------------
COPY conf/options.xl2tpd    /etc/ppp/options.xl2tpd
COPY conf/chap-secrets      /etc/ppp/chap-secrets
COPY conf/chap-secrets      /etc/ppp/pap-secrets

# --- built-in verification client (used by verify.sh) -----------------------
COPY client/                /opt/l2tp-client/

COPY entrypoint.sh          /entrypoint.sh

RUN chmod 600 /etc/ipsec.secrets /etc/ppp/chap-secrets /etc/ppp/pap-secrets \
    && chmod +x /entrypoint.sh /opt/l2tp-client/*.sh \
    && mkdir -p /var/run/xl2tpd /var/log \
    && touch /var/log/charon.log /var/log/xl2tpd.log /var/log/pppd.log

EXPOSE 500/udp 4500/udp 1701/udp

ENTRYPOINT ["/entrypoint.sh"]
