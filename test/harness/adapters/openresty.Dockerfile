# OpenResty with lua-resty-openssl (our core needs HMAC/SHA-256/CSPRNG) plus
# the portable Lua core and the openresty adapter shim. Context = repo root.
#
# alpine-fat is the variant that carries opm's own dependencies (perl et al).
FROM openresty/openresty:alpine-fat
RUN opm get fffonion/lua-resty-openssl
COPY core/lua/jitaccess                /usr/local/share/jitaccess/jitaccess
COPY adapters/openresty/lib/jitaccess  /usr/local/share/jitaccess/lib/jitaccess
