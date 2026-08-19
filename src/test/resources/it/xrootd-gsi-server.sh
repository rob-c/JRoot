#!/bin/bash
#
# A throwaway XRootD server that speaks GSI, for the interop test.
#
# It mints its own world: a test CA, a host certificate for this machine, a
# user certificate and an X.509 proxy from it, then starts the official
# `xrootd` binary bound to GSI only, exporting one read/write directory. The
# point is that nothing in the server side is ours -- the client under test is
# the only piece of JRoot in the picture, so an interop bug has nowhere to hide.
#
#   xrootd-gsi-server.sh start BASE PORT   provision and run; prints key=value
#   xrootd-gsi-server.sh stop  BASE        stop it and take the sockets away
#
# Everything it makes lives under BASE, except the admin socket directory: the
# UNIX socket xrootd binds there has a short path limit that a deep temporary
# directory blows straight through, so that one lives in $TMPDIR.
set -euo pipefail

OPENSSL=${OPENSSL:-/usr/bin/openssl}
EXPORT=/gsidata

stop() {
    local base=$1
    [ -f "$base/pid" ] && kill "$(cat "$base/pid")" 2>/dev/null || true
    [ -f "$base/adminpath" ] && rm -rf "$(cat "$base/adminpath")" || true
    return 0
}

start() {
    local base=$1 port=$2
    local fqdn admin hash subject
    fqdn=$(hostname -f 2>/dev/null || hostname)
    mkdir -p "$base"/{ca,server,user,certs} "$base$EXPORT"
    admin=$(mktemp -d "${TMPDIR:-/tmp}/jroot-xrd-XXXXXX")
    echo "$admin" > "$base/adminpath"

    osl() { "$OPENSSL" "$@" >/dev/null 2>&1; }

    # The CA, under the hashed name and with the signing policy XrdSecgsi wants
    # before it will accept anything the CA has signed.
    osl req -x509 -nodes -newkey rsa:2048 -days 1 -subj "/O=JRootTest/CN=JRootTest CA" \
        -keyout "$base/ca/ca.key" -out "$base/ca/ca.pem"
    hash=$("$OPENSSL" x509 -in "$base/ca/ca.pem" -noout -hash)
    subject=$("$OPENSSL" x509 -in "$base/ca/ca.pem" -noout -subject -nameopt compat |
              sed 's/^subject= //')
    cp "$base/ca/ca.pem" "$base/certs/$hash.0"
    printf "access_id_CA X509 '%s' pos_rights globus:/CN=*\n" "$subject" \
        > "$base/certs/$hash.signing_policy"

    signed() {  # common-name key-file cert-file
        osl req -nodes -newkey rsa:2048 -subj "/O=JRootTest/CN=$1" \
            -keyout "$2" -out "$base/csr.pem"
        osl x509 -req -in "$base/csr.pem" -CA "$base/ca/ca.pem" -CAkey "$base/ca/ca.key" \
            -CAcreateserial -days 1 -out "$3"
    }
    signed "$fqdn" "$base/server/hostkey.pem" "$base/server/hostcert.pem"
    signed "JRoot Test User" "$base/user/userkey.pem" "$base/user/usercert.pem"
    chmod 600 "$base/user/userkey.pem" "$base/server/hostkey.pem"

    # The proxy is minted by the official tool, so the thing the client is asked
    # to present is exactly what a real user would be holding.
    X509_CERT_DIR=$base/certs X509_USER_PROXY=$base/user/proxy.pem \
        xrdgsiproxy init -cert "$base/user/usercert.pem" -key "$base/user/userkey.pem" \
            -out "$base/user/proxy.pem" -certdir "$base/certs" -valid 1:00 \
            </dev/null >"$base/proxy.log" 2>&1 || true
    [ -s "$base/user/proxy.pem" ] || { echo "xrdgsiproxy minted no proxy:" >&2
                                       cat "$base/proxy.log" >&2; exit 1; }

    cat > "$base/xrootd.cfg" <<CFG
xrd.port $port
all.adminpath $admin
all.pidpath $admin
all.export $EXPORT r/w
oss.localroot $base
xrootd.seclib libXrdSec.so
sec.protocol /usr/lib64 gsi -certdir:$base/certs -cert:$base/server/hostcert.pem \
-key:$base/server/hostkey.pem -crl:0 -gmapopt:10 -dlgpxy:0
sec.protbind * only gsi
CFG
    xrootd -c "$base/xrootd.cfg" -l "$base/xrootd.log" -n jroot >/dev/null 2>&1 &
    echo $! > "$base/pid"

    for _ in $(seq 100); do
        ss -tln | grep -q ":$port " && break
        sleep 0.2
    done
    ss -tln | grep -q ":$port " || { echo "xrootd did not listen on $port:" >&2
                                     tail -20 "$base/xrootd.log" >&2; stop "$base"; exit 1; }

    echo "url=root://$fqdn:$port/$EXPORT"
    echo "storage=$base$EXPORT"
    echo "proxy=$base/user/proxy.pem"
    echo "certs=$base/certs"
    echo "log=$base/xrootd.log"
}

case ${1:-} in
    start) start "${2:?base directory}" "${3:?port}" ;;
    stop)  stop  "${2:?base directory}" ;;
    *)     echo "usage: $0 start BASE PORT | stop BASE" >&2; exit 2 ;;
esac
