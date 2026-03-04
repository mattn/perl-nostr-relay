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

# Database connection
my $db_url = $ENV{DATABASE_URL} || die "DATABASE_URL not set";

my ($user, $pass, $host, $port, $dbname) = $db_url =~ m{^[^:]+://([^:]+):([^@]+)@([^:]+):(\d+)/([^/?]+)}
    or die "Invalid DATABASE_URL format";
$pass =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;  # URL decode password

my $dbh = DBI->connect(
    "dbi:Pg:dbname=$dbname;host=$host;port=$port",
    $user,
    $pass,
    {AutoCommit => 1, RaiseError => 1, pg_enable_utf8 => 1}
) or die "Cannot connect to database: $DBI::errstr";

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
    eval {
        $dbh->do(
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

    # Validate limit (positive integer, max 5000)
    if (exists $filter->{limit}) {
        return 0 unless $filter->{limit} =~ /^\d+$/ && $filter->{limit} >= 1 && $filter->{limit} <= 5000;
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
    my $sth = $dbh->prepare($query);
    $sth->execute(@$params);
    
    while (my $row = $sth->fetchrow_hashref) {
        my $ev = {
            id => $row->{id},
            pubkey => $row->{pubkey},
            created_at => $row->{created_at},
            kind => $row->{kind},
            tags => decode_json($row->{tags}),
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

tcp_server '0.0.0.0', 8080, sub {
    my ($fh) = @_;
    
    my $conn_id = sprintf("conn%d", ++$conn_counter);
    infof("New connection: %s", $conn_id);
    
    my $hs = Protocol::WebSocket::Handshake::Server->new;
    my $frame = Protocol::WebSocket::Frame->new;
    
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
            $hs->parse($chunk);
            if ($hs->is_done) {
                my $response = $hs->to_string;
                $response =~ s/Upgrade: WebSocket/Upgrade: websocket/;
                $handle->push_write($response);
            }
            return;
        }
        
        $frame->append($chunk);
        
        while (my $msg = $frame->next_bytes) {
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
    });
}, sub {
    my ($fh, $host, $port) = @_;
    infof("Nostr relay running on ws://%s:%s/", $host, $port);
};

AnyEvent->condvar->recv;
