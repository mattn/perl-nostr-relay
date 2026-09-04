#!/usr/bin/env perl
use strict;
use warnings;
use AnyEvent;
use AnyEvent::Socket;
use AnyEvent::Handle;
use Protocol::WebSocket::Handshake::Server;
use Protocol::WebSocket::Frame;
use JSON::PP qw(decode_json encode_json);
use DBI;
use Digest::SHA qw(sha256);
use Crypt::PK::ECC::Schnorr;
use Log::Minimal;
use Data::Dumper;
use File::Basename qw(dirname);

my $public_dir = dirname(__FILE__) . '/public';

my %mime_types = (
    html => 'text/html',
    css  => 'text/css',
    js   => 'application/javascript',
    json => 'application/json',
    png  => 'image/png',
    jpg  => 'image/jpeg',
    jpeg => 'image/jpeg',
    gif  => 'image/gif',
    svg  => 'image/svg+xml',
    ico  => 'image/x-icon',
);

# Database connection
my $db_url = $ENV{DATABASE_URL} || die "DATABASE_URL not set";

my ($user, $pass, $host, $port, $dbname) = $db_url =~ m{^[^:]+://([^:]+):([^@]+)@([^:]+):(\d+)/([^/?]+)}
    or die "Invalid DATABASE_URL format";
$pass =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;  # URL decode password

sub connect_db {
    return DBI->connect(
        "dbi:Pg:dbname=$dbname;host=$host;port=$port",
        $user,
        $pass,
        {AutoCommit => 1, RaiseError => 1, pg_enable_utf8 => 1}
    );
}

my $dbh = connect_db() or die "Cannot connect to database: $DBI::errstr";

sub get_dbh {
    unless ($dbh && eval { $dbh->ping }) {
        infof("Database connection lost, reconnecting");
        $dbh = connect_db();
    }
    return $dbh;
}

# Global subscriptions across all connections
my $all_subs = {};
my $conn_counter = 0;

sub build_query {
    my ($filter) = @_;
    my @where;
    my @params;
    
    if ($filter->{ids}) {
        push @where, "id = ANY(?)";
        push @params, $filter->{ids};
    }
    if ($filter->{authors}) {
        push @where, "pubkey = ANY(?)";
        push @params, $filter->{authors};
    }
    if ($filter->{kinds}) {
        push @where, "kind = ANY(?)";
        push @params, $filter->{kinds};
    }
    if ($filter->{since}) {
        push @where, "created_at >= ?";
        push @params, $filter->{since};
    }
    if ($filter->{until}) {
        push @where, "created_at <= ?";
        push @params, $filter->{until};
    }

    # Tag filters (e.g. #e, #p): tagvalues && ? narrows via the GIN index,
    # the EXISTS clause checks the tag name exactly
    for my $key (sort keys %$filter) {
        if ($key =~ /^#([a-zA-Z])$/) {
            my $tag_name = $1;
            my $values = $filter->{$key};
            next unless ref $values eq 'ARRAY' && @$values;
            push @where, "(tagvalues && ?::text[] AND EXISTS (SELECT 1 FROM jsonb_array_elements(tags) tag WHERE tag->>0 = ? AND tag->>1 = ANY(?)))";
            push @params, $values, $tag_name, $values;
        }
    }

    my $where_clause = @where ? "WHERE " . join(" AND ", @where) : "";
    my $limit = $filter->{limit} // 100;
    
    return ("SELECT id, pubkey, created_at, kind, tags, content, sig FROM event $where_clause ORDER BY created_at DESC LIMIT ?", [@params, $limit]);
}

sub match_filter {
    my ($ev, $filter) = @_;
    
    return 0 unless $filter;
    
    # Check ids filter
    if ($filter->{ids} && ref $filter->{ids} eq 'ARRAY') {
        return 0 unless grep { $_ eq $ev->{id} } @{$filter->{ids}};
    }
    
    # Check authors filter
    if ($filter->{authors} && ref $filter->{authors} eq 'ARRAY') {
        return 0 unless grep { $_ eq $ev->{pubkey} } @{$filter->{authors}};
    }
    
    # Check kinds filter
    if ($filter->{kinds} && ref $filter->{kinds} eq 'ARRAY') {
        return 0 unless grep { $_ == $ev->{kind} } @{$filter->{kinds}};
    }
    
    # Check since filter
    if ($filter->{since} && $ev->{created_at} < $filter->{since}) {
        return 0;
    }
    
    # Check until filter
    if ($filter->{until} && $ev->{created_at} > $filter->{until}) {
        return 0;
    }
    
    # Check tags filters (e.g., #e, #p)
    for my $key (keys %$filter) {
        if ($key =~ /^#([a-zA-Z])$/) {
            my $tag_name = $1;
            my $filter_values = $filter->{$key};
            next unless ref $filter_values eq 'ARRAY';

            # If event has no tags, it cannot match tag filters
            return 0 unless $ev->{tags} && ref $ev->{tags} eq 'ARRAY';

            my @matching_tags = grep {
                ref $_ eq 'ARRAY' && $_->[0] eq $tag_name
            } @{$ev->{tags}};

            return 0 unless @matching_tags;

            my $found = 0;
            for my $tag (@matching_tags) {
                if ($tag->[1] && grep { $_ eq $tag->[1] } @$filter_values) {
                    $found = 1;
                    last;
                }
            }
            return 0 unless $found;
        }
    }
    
    return 1;
}

sub verify_event {
    my ($ev) = @_;
    
    # Check required fields
    return (0, "invalid: missing required fields") unless 
        $ev->{id} && $ev->{pubkey} && defined($ev->{created_at}) && 
        defined($ev->{kind}) && $ev->{tags} && defined($ev->{content}) && $ev->{sig};
    
    # Verify event ID (sha256 hash)
    my $serialized = encode_json([
        0,
        $ev->{pubkey},
        $ev->{created_at},
        $ev->{kind},
        $ev->{tags},
        $ev->{content}
    ]);
    my $computed_id = unpack('H*', sha256($serialized));
    
    return (0, "invalid: event id does not match") unless $computed_id eq $ev->{id};
    
    # Verify Schnorr signature (BIP340)
    my $sig_valid;
    eval {
        my $schnorr = Crypt::PK::ECC::Schnorr->new();
        # Import public key with secp256k1 curve
        $schnorr->import_key_raw(pack('H*', '02' . $ev->{pubkey}), 'secp256k1');

        my $sig_bytes = pack('H*', $ev->{sig});
        my $msg_bytes = pack('H*', $ev->{id});

        $sig_valid = $schnorr->verify_message($msg_bytes, $sig_bytes);
    };

    return (0, "invalid: signature verification error: $@") if $@;
    return (0, "invalid: signature verification failed") unless $sig_valid;
    return (1, "");
}

sub validate_delegation {
    my ($ev) = @_;

    # NIP-26: Delegated Event Signing
    # Find delegation tag: ["delegation", <delegator pubkey>, <conditions>, <sig>]
    my $delegation_tag;
    for my $tag (@{$ev->{tags} // []}) {
        if (ref $tag eq 'ARRAY' && @$tag >= 4 && ($tag->[0] // '') eq 'delegation') {
            $delegation_tag = $tag;
            last;
        }
    }

    # No delegation tag, nothing to validate
    return (1, "") unless $delegation_tag;

    return (0, "invalid: malformed delegation tag") unless @$delegation_tag == 4;

    my ($delegator_pubkey, $conditions, $signature) = @{$delegation_tag}[1, 2, 3];

    return (0, "invalid: malformed delegation tag") unless
        defined($delegator_pubkey) && $delegator_pubkey ne '' &&
        defined($conditions) && $conditions ne '' &&
        defined($signature) && $signature ne '';

    # Delegator pubkey must be a 64 char hex string
    return (0, "invalid: malformed delegation tag")
        unless $delegator_pubkey =~ /^[0-9a-f]{64}$/i;

    return (0, "invalid: delegation conditions not satisfied")
        unless validate_delegation_conditions($ev, $conditions);

    return (0, "invalid: delegation signature verification failed")
        unless verify_delegation_signature($ev->{pubkey}, $delegator_pubkey, $conditions, $signature);

    return (1, "");
}

sub validate_delegation_conditions {
    my ($ev, $conditions) = @_;

    my $kind_allowed = 0;
    my $created_at_valid = 1;

    for my $condition (split /&/, $conditions) {
        if ($condition =~ /^kind=(\d+)$/) {
            $kind_allowed = 1 if $ev->{kind} == $1;
        }
        elsif ($condition =~ /^created_at<(\d+)$/) {
            $created_at_valid = 0 if $ev->{created_at} >= $1;
        }
        elsif ($condition =~ /^created_at>(\d+)$/) {
            $created_at_valid = 0 if $ev->{created_at} <= $1;
        }
    }

    return $kind_allowed && $created_at_valid;
}

sub verify_delegation_signature {
    my ($delegatee_pubkey, $delegator_pubkey, $conditions, $signature) = @_;

    # Signature must be a 64 byte hex string
    return 0 unless $signature =~ /^[0-9a-f]{128}$/i;

    # Delegation token: sha256("nostr:delegation:<delegatee pubkey>:<conditions>")
    my $token = "nostr:delegation:$delegatee_pubkey:$conditions";
    my $hash = sha256($token);

    # Verify Schnorr signature (BIP340) by the delegator
    my $sig_valid;
    eval {
        my $schnorr = Crypt::PK::ECC::Schnorr->new();
        # Import public key with secp256k1 curve
        $schnorr->import_key_raw(pack('H*', '02' . $delegator_pubkey), 'secp256k1');

        my $sig_bytes = pack('H*', $signature);

        $sig_valid = $schnorr->verify_message($hash, $sig_bytes);
    };

    return 0 if $@;
    return $sig_valid ? 1 : 0;
}

sub check_event {
    my ($ev) = @_;

    # Basic validation checks - returns 1 if valid, 0 if invalid
    return 0 unless ref $ev eq 'HASH';
    # Check if id is valid hex string (64 chars)
    return 0 unless $ev->{id} && $ev->{id} =~ /^[0-9a-f]{64}$/i;
    # Check if pubkey is valid hex string (64 chars)
    return 0 unless $ev->{pubkey} && $ev->{pubkey} =~ /^[0-9a-f]{64}$/i;
    # Check if sig is valid hex string (128 chars)
    return 0 unless $ev->{sig} && $ev->{sig} =~ /^[0-9a-f]{128}$/i;
    # Check if created_at is a valid integer
    return 0 unless defined($ev->{created_at}) && $ev->{created_at} =~ /^\d+$/;
    # Check if kind is a valid integer
    return 0 unless defined($ev->{kind}) && $ev->{kind} =~ /^\d+$/;
    # Check if tags is an array
    return 0 unless defined($ev->{tags}) && ref $ev->{tags} eq 'ARRAY';
    # Check if content exists (can be empty string)
    return 0 unless defined($ev->{content});

    return 1;
}

sub do_event {
    my ($handle, $ev) = @_;

    # Basic validation checks
    unless (check_event($ev)) {
        my $response = Protocol::WebSocket::Frame->new(encode_json(["OK", "", JSON::PP::false, "invalid: invalid JSON"]))->to_bytes;
        $handle->push_write($response);
        return 0;
    }

    my ($valid, $err_msg) = verify_event($ev);
    if (!$valid) {
        my $response = Protocol::WebSocket::Frame->new(encode_json(["OK", $ev->{id}//"", JSON::PP::false, $err_msg]))->to_bytes;
        $handle->push_write($response);
        return 0;
    }

    # NIP-26: validate delegation tag if present
    my ($delegation_valid, $delegation_err) = validate_delegation($ev);
    if (!$delegation_valid) {
        my $response = Protocol::WebSocket::Frame->new(encode_json(["OK", $ev->{id}, JSON::PP::false, $delegation_err]))->to_bytes;
        $handle->push_write($response);
        return 0;
    }

    # NIP-09: deletion request; run before the insert so resending an
    # already stored deletion event still deletes its targets
    if ($ev->{kind} == 5) {
        eval {
            my $dbh = get_dbh();
            for my $tag (@{$ev->{tags} // []}) {
                next unless ref $tag eq 'ARRAY' && ($tag->[0] // '') eq 'e' && $tag->[1];
                my $row = $dbh->selectrow_hashref("SELECT kind, pubkey, tags FROM event WHERE id = ?", undef, $tag->[1]);
                next unless $row;
                if ($row->{kind} == 1059) {
                    # Gift wrap: the recipient (first p tag) may delete it
                    my $tags = eval { decode_json($row->{tags}) } // [];
                    next unless ref $tags eq 'ARRAY' && ref $tags->[0] eq 'ARRAY'
                        && ($tags->[0][0] // '') eq 'p' && ($tags->[0][1] // '') eq $ev->{pubkey};
                    $dbh->do("DELETE FROM event WHERE id = ?", undef, $tag->[1]);
                }
                else {
                    $dbh->do("DELETE FROM event WHERE id = ? AND pubkey = ?", undef, $tag->[1], $ev->{pubkey});
                }
            }
        };
        if ($@) {
            warnf("Deletion failed: %s", $@);
            my $response = Protocol::WebSocket::Frame->new(encode_json(["OK", $ev->{id}, JSON::PP::false, "error: failed to delete event"]))->to_bytes;
            $handle->push_write($response);
            return 0;
        }
    }

    eval {
        get_dbh()->do(
            "INSERT INTO event (id, pubkey, created_at, kind, tags, content, sig) VALUES (?, ?, ?, ?, ?, ?, ?)",
            undef,
            $ev->{id}, $ev->{pubkey}, $ev->{created_at}, $ev->{kind},
            encode_json($ev->{tags} // []), $ev->{content} // '', $ev->{sig}
        );
    };
    if ($@) {
        my $err = $@ =~ /duplicate key/ ? "duplicate: event already exists" : "error: $@";
        my $response = Protocol::WebSocket::Frame->new(encode_json(["OK", $ev->{id}, JSON::PP::false, $err]))->to_bytes;
        $handle->push_write($response);
        return 0;
    }

    my $response = Protocol::WebSocket::Frame->new(encode_json(["OK", $ev->{id}, JSON::PP::true, ""]))->to_bytes;
    $handle->push_write($response);
    return 1;
}

sub check_filter {
    my ($filter) = @_;

    # Validate filter is an object - returns 1 if valid, 0 if invalid
    return 0 unless defined($filter) && ref $filter eq 'HASH';
    # Validate filter fields
    for my $field (qw(ids authors kinds)) {
        if (exists $filter->{$field}) {
            return 0 unless ref $filter->{$field} eq 'ARRAY';
        }
    }

    # Validate ids format (64 hex chars each)
    if (exists $filter->{ids}) {
        for my $id (@{$filter->{ids}}) {
            return 0 unless $id =~ /^[0-9a-f]{64}$/i;
        }
    }

    # Validate authors format (64 hex chars each)
    if (exists $filter->{authors}) {
        for my $author (@{$filter->{authors}}) {
            return 0 unless $author =~ /^[0-9a-f]{64}$/i;
        }
    }

    # Validate kinds (non-negative integers)
    if (exists $filter->{kinds}) {
        for my $kind (@{$filter->{kinds}}) {
            return 0 unless $kind =~ /^\d+$/;
        }
    }

    # Validate since/until (integers)
    for my $field (qw(since until)) {
        if (exists $filter->{$field}) {
            return 0 unless $filter->{$field} =~ /^\d+$/;
        }
    }

    # Validate limit (non-negative integer, max 5000).  Zero requests no
    # stored events while leaving the subscription active after EOSE.
    if (exists $filter->{limit}) {
        return 0 unless $filter->{limit} =~ /^\d+$/ && $filter->{limit} <= 5000;
    }

    # Validate tag filters (#e, #p, ...): must be arrays of strings
    for my $key (keys %$filter) {
        if ($key =~ /^#[a-zA-Z]$/) {
            return 0 unless ref $filter->{$key} eq 'ARRAY';
            for my $value (@{$filter->{$key}}) {
                return 0 if ref $value || !defined $value;
            }
        }
    }

    return 1;
}


sub do_req {
    my ($handle, $sid, $filter, $conn_id) = @_;
    
    # Validate subscription id
    if (!defined($sid) || $sid eq '') {
        my $response = Protocol::WebSocket::Frame->new(encode_json(["NOTICE", "invalid: subscription id is required"]))->to_bytes;
        $handle->push_write($response);
        return;
    }
    
    # Validate filter is an object
    unless (check_filter($filter)) {
        my $response = Protocol::WebSocket::Frame->new(encode_json(["NOTICE", "invalid: filter must be an object"]))->to_bytes;
        $handle->push_write($response);
        return;
    }
    
    my $sub_key = "$conn_id:$sid";
    $all_subs->{$sub_key} = {
        filter => $filter,
        handle => $handle,
    };

    my ($query, $params) = build_query($filter);
    my @rows;
    eval {
        my $sth = get_dbh()->prepare($query);
        $sth->execute(@$params);
        while (my $row = $sth->fetchrow_hashref) {
            push @rows, $row;
        }
    };
    if ($@) {
        warnf("Query failed: %s", $@);
        delete $all_subs->{$sub_key};
        my $response = Protocol::WebSocket::Frame->new(encode_json(["CLOSED", $sid, "error: could not query events"]))->to_bytes;
        $handle->push_write($response);
        return;
    }

    for my $row (@rows) {
        my $ev = {
            id => $row->{id},
            pubkey => $row->{pubkey},
            created_at => $row->{created_at},
            kind => $row->{kind},
            tags => (eval { decode_json($row->{tags}) } // []),
            content => $row->{content},
            sig => $row->{sig}
        };
        my $response = Protocol::WebSocket::Frame->new(encode_json(["EVENT", $sid, $ev]))->to_bytes;
        $handle->push_write($response);
    }

    my $eose = Protocol::WebSocket::Frame->new(encode_json(["EOSE", $sid]))->to_bytes;
    $handle->push_write($eose);
}

sub do_broadcast {
    my ($ev) = @_;

    for my $sub_key (keys %$all_subs) {
        my $sub = $all_subs->{$sub_key};
        my $filter = $sub->{filter};
        my $handle = $sub->{handle};
        
        next unless $handle;
        next unless match_filter($ev, $filter);

        my ($conn_id, $sid) = split /:/, $sub_key, 2;
        my $response = Protocol::WebSocket::Frame->new(encode_json(["EVENT", $sid, $ev]))->to_bytes;
        
        eval { $handle->push_write($response); };
        if ($@) {
            warnf("Failed to broadcast to %s: %s", $sub_key, $@);
            delete $all_subs->{$sub_key};
        }
    }
}

sub http_response {
    my ($handle, $status, $headers, $body) = @_;

    my $response = "HTTP/1.1 $status\r\n";
    $response .= "$_: $headers->{$_}\r\n" for sort keys %$headers;
    $response .= "Content-Length: " . length($body) . "\r\n";
    $response .= "Connection: close\r\n";
    $response .= "\r\n";
    $response .= $body;
    $handle->push_write($response);
    $handle->on_drain(sub { $_[0]->destroy });
}

sub serve_nip11 {
    my ($handle) = @_;

    my $info = {
        name => $ENV{RELAY_NAME} // 'Perl Nostr Relay',
        description => $ENV{RELAY_DESCRIPTION} // 'A simple Nostr relay implementation in Perl',
        pubkey => $ENV{RELAY_PUBKEY} // '',
        contact => $ENV{RELAY_CONTACT} // '',
        supported_nips => [1, 2, 4, 9, 11, 12, 15, 16, 20, 22, 26, 28, 33, 40, 70],
        software => 'perl-nostr-relay',
        version => '0.0.1',
    };
    $info->{url} = $ENV{RELAY_URL} if $ENV{RELAY_URL};
    $info->{icon} = $ENV{RELAY_ICON} if $ENV{RELAY_ICON};

    http_response($handle, '200 OK', {
        'Content-Type' => 'application/nostr+json',
        'Access-Control-Allow-Origin' => '*',
        'Access-Control-Allow-Headers' => 'Content-Type, Accept',
        'Access-Control-Allow-Methods' => 'GET',
    }, encode_json($info));
}

sub serve_static {
    my ($handle, $path) = @_;

    $path =~ s/[?#].*//;
    $path =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
    $path = '/index.html' if $path eq '/';

    if ($path =~ /\.\./ || $path !~ m{^/[0-9A-Za-z._\-/]+$}) {
        http_response($handle, '404 Not Found', {'Content-Type' => 'text/plain'}, '404 Not Found');
        return;
    }

    my ($ext) = $path =~ /\.([0-9A-Za-z]+)$/;
    my $file = "$public_dir$path";
    unless ($ext && $mime_types{lc $ext} && -f $file) {
        http_response($handle, '404 Not Found', {'Content-Type' => 'text/plain'}, '404 Not Found');
        return;
    }

    open my $fh, '<:raw', $file or do {
        http_response($handle, '404 Not Found', {'Content-Type' => 'text/plain'}, '404 Not Found');
        return;
    };
    my $body = do { local $/; <$fh> };
    close $fh;

    http_response($handle, '200 OK', {'Content-Type' => $mime_types{lc $ext}}, $body);
}

tcp_server '0.0.0.0', 8080, sub {
    my ($fh) = @_;
    
    my $conn_id = sprintf("conn%d", ++$conn_counter);
    infof("New connection: %s", $conn_id);
    
    my $hs = Protocol::WebSocket::Handshake::Server->new;
    my $frame = Protocol::WebSocket::Frame->new(max_payload_size => 1024 * 1024);
    my $http_buf = '';
    my $is_websocket = 0;
    
    my $handle; $handle = AnyEvent::Handle->new(
        fh => $fh,
        on_error => sub {
            my ($hdl, $fatal, $msg) = @_;
            warnf("Connection error: %s (fatal=%s)", $msg, $fatal) if $fatal;
            # Clean up subscriptions for this connection
            for my $key (keys %$all_subs) {
                delete $all_subs->{$key} if $key =~ /^\Q$conn_id\E:/;
            }
            $hdl->destroy;
        },
        on_eof => sub {
            infof("Connection closed: %s", $conn_id);
            # Clean up subscriptions for this connection
            for my $key (keys %$all_subs) {
                delete $all_subs->{$key} if $key =~ /^\Q$conn_id\E:/;
            }
            $handle->destroy;
        },
    );
    
    $handle->on_read(sub {
        my $chunk = $handle->{rbuf};
        $handle->{rbuf} = '';
        
        if (!$hs->is_done) {
            if (!$is_websocket) {
                $http_buf .= $chunk;
                return unless $http_buf =~ /\r\n\r\n/;

                my ($head) = split /\r\n\r\n/, $http_buf, 2;
                my @lines = split /\r\n/, $head;
                my $request_line = shift @lines // '';
                my %headers;
                for my $line (@lines) {
                    my ($k, $v) = split /:\s*/, $line, 2;
                    $headers{lc $k} = $v // '' if defined $k;
                }

                if (($headers{upgrade} // '') =~ /websocket/i) {
                    $is_websocket = 1;
                    $chunk = $http_buf;
                }
                elsif (($headers{accept} // '') =~ m{application/nostr\+json}) {
                    my ($path) = $request_line =~ m{^\S+\s+(\S+)};
                    infof("NIP-11 request: %s", $path // '/');
                    serve_nip11($handle);
                    return;
                }
                else {
                    my ($path) = $request_line =~ m{^GET\s+(\S+)};
                    infof("HTTP request: %s", $path // '(bad request)');
                    serve_static($handle, $path // '/');
                    return;
                }
            }
            $hs->parse($chunk);
            if ($hs->is_done) {
                my $response = $hs->to_string;
                $response =~ s/Upgrade: WebSocket/Upgrade: websocket/;
                $handle->push_write($response);
            }
            return;
        }
        
        my $parsed_ok = eval {
        $frame->append($chunk);

        while (defined(my $msg = $frame->next_bytes)) {
            if ($frame->is_ping) {
                $handle->push_write(Protocol::WebSocket::Frame->new(type => 'pong', buffer => $msg)->to_bytes);
                next;
            }
            if ($frame->is_close) {
                $handle->push_write(Protocol::WebSocket::Frame->new(type => 'close')->to_bytes);
                $handle->push_shutdown;
                last;
            }
            next if $frame->is_pong;

            infof("Received message: %s", substr($msg, 0, 100) . (length($msg) > 100 ? "..." : ""));

            my $data = eval { decode_json($msg) };
            if ($@ || ref $data ne 'ARRAY') {
                warnf("Invalid JSON or not an array: %s", $@) if $@;
                next;
            }
            
            my $type = $data->[0] // '';
            debugf("Message type: %s", $type);
            
            if ($type eq 'EVENT') {
                my $ev = $data->[1];

                if (do_event($handle, $ev)) {
                    do_broadcast($ev);
                }
            }
            elsif ($type eq 'REQ') {
                my $sid = $data->[1];
                my $filter = $data->[2] // {};
                
                do_req($handle, $sid, $filter, $conn_id);
            }
            elsif ($type eq 'CLOSE') {
                my $sid = $data->[1];
                my $sub_key = "$conn_id:$sid";
                delete $all_subs->{$sub_key};
            }
        }
        1;
        };
        unless ($parsed_ok) {
            warnf("Closing %s due to frame error: %s", $conn_id, $@);
            for my $key (keys %$all_subs) {
                delete $all_subs->{$key} if $key =~ /^\Q$conn_id\E:/;
            }
            $handle->destroy;
        }
    });
}, sub {
    my ($fh, $host, $port) = @_;
    infof("Nostr relay running on ws://%s:%s/", $host, $port);
};

AnyEvent->condvar->recv;
