FROM alpine:3.19 AS builder

RUN apk add --no-cache \
    perl \
    perl-dev \
    perl-app-cpanminus \
    make \
    gcc \
    g++ \
    libc-dev \
    postgresql-dev \
    gmp-dev

WORKDIR /build

# Install Perl dependencies
RUN cpanm --notest \
    AnyEvent \
    Protocol::WebSocket \
    JSON::PP \
    DBI \
    DBD::Pg \
    Digest::SHA \
    Math::GMPz \
    Crypt::PK::ECC::Schnorr \
    Log::Minimal

COPY nostr-relay.pl /app/nostr-relay.pl

# Try to create a minimal runtime
FROM alpine:3.19

RUN apk add --no-cache \
    perl \
    postgresql-libs \
    gmp

# Copy Perl modules from builder
COPY --from=builder /usr/local/share/perl5 /usr/local/share/perl5
COPY --from=builder /usr/local/lib/perl5 /usr/local/lib/perl5

COPY --from=builder /app/nostr-relay.pl /app/nostr-relay.pl
COPY public /app/public

WORKDIR /app

ENV PERL5LIB=/usr/local/lib/perl5/site_perl:/usr/local/share/perl5/site_perl

EXPOSE 8080

CMD ["perl", "nostr-relay.pl"]
