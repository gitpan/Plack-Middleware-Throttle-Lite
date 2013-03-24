package Plack::Middleware::Throttle::Lite;

# ABSTRACT: Requests throttling for Plack

use strict;
use warnings;
use feature ':5.10';
use parent 'Plack::Middleware';
use Plack::Util::Accessor qw(limits maxreq units backend routes blacklist whitelist def_maxreq def_units def_backend privileged);
use Scalar::Util qw(reftype);
use List::MoreUtils qw(any);
use Plack::Util;
use Carp ();
use Net::CIDR::Lite;

our $VERSION = '0.01'; # VERSION
our $AUTHORITY = 'cpan:CHIM'; # AUTHORITY

#
# Some important routines
sub prepare_app {
    my ($self) = @_;

    $self->def_maxreq(199);
    $self->def_units('req/hour');
    $self->def_backend('Simple');

    $self->_normalize_limits;
    $self->_initialize_backend;
    $self->_normalize_routes;
    $self->blacklist($self->_initialize_accesslist($self->blacklist));
    $self->whitelist($self->_initialize_accesslist($self->whitelist));

    $self->backend->reqs_max($self->maxreq);
    $self->backend->units($self->units);
}

#
# Execute middleware
sub call {
    my ($self, $env) = @_;

    my $response;

    if ($self->have_to_throttle($env)) {

        return $self->reject_request(blacklist => 503) if $self->is_remote_blacklisted($env);

        # update client id
        $self->backend->requester_id($self->requester_id($env));

        # update
        $self->privileged($self->is_remote_whitelisted($env));

        $response = $self->is_allowed
            ? $self->app->($env)
            : $self->reject_request(ratelimit => 503);

        $self->response_cb($response, sub {
            $self->modify_headers(@_);
        });
    }
    else {
        $response = $self->app->($env);
    }

    $response;
}

#
# Rejects incoming request with some reason
sub reject_request {
    my ($self, $reason, $code) = @_;

    my $reasons = {
        blacklist => 'Access from blacklisted IP address cannot be done!',
        ratelimit => 'Limit exceeded!',
    };

    [
        $code,
        [ 'Content-Type' => 'text/plain', ],
        [ $reasons->{$reason} ]
    ];
}

#
# Rate limit normalization
sub _normalize_limits {
    my ($self) = @_;

    my $units = {
        'm' => 'req/min',
        'h' => 'req/hour',
        'd' => 'req/day',
    };

    my $limits_re = qr{^(?<numreqs>\d*)(\s*)(r|req)(\/|\sper\s)(?<units>h|hour|d|day|m|min).*};

    if ($self->limits) {
        my $t_limits = lc($self->limits);
        $t_limits =~ s/\s+/ /g;
        $t_limits =~ /$limits_re/;
        $self->maxreq($+{numreqs} || $self->def_maxreq);
        $self->units($units->{$+{units}} || $self->def_units)
    }
    else {
        $self->maxreq($self->def_maxreq);
        $self->units($self->def_units)
    }
}

#
# Storage backend
sub _initialize_backend {
    my ($self) = @_;

    my ($class, $args) = ($self->def_backend, {});

    if ($self->backend) {
        given (reftype $self->backend) {
            when (undef)   { ($class, $args) = ($self->backend, {})            }
            when ('ARRAY') { ($class, $args) = @{ $self->backend }             }
            default        { Carp::croak 'Expected scalar or array reference!' }
        }
    }

    my $backend = Plack::Util::load_class($class, 'Plack::Middleware::Throttle::Lite::Backend');

    $self->backend($backend->new($args));
}

#
# Routes' normalization
sub _normalize_routes {
    my ($self) = @_;

    my $routes = [];

    if ($self->routes) {
        given (reftype $self->routes) {
            when (undef) {
                $routes = [ $self->routes ];
            }
            when ('REGEXP') {
                $routes = [ $self->routes ];
            }
            when ('ARRAY') {
                $routes = $self->routes;
            }
            default {
                Carp::croak 'Expected scalar, regex or array reference!';
            }
        }
    }

    $self->routes($routes);
}

#
# Adds extra headers to response
sub modify_headers {
    my ($self, $response) = @_;
    my $headers = $response->[1];

    my %info = (
        Limit => $self->privileged ? 'unlimited' : $self->maxreq,
        Units => $self->units,
        Used  => $self->backend->reqs_done,
    );

    $info{Expire} = $self->backend->expire_in if ($self->backend->reqs_done >= $self->maxreq) && !$self->privileged;

    map { Plack::Util::header_set($headers, 'X-Throttle-Lite-' . $_, $info{$_}) } sort keys %info;

    $response;
}

#
# Checks if requested path should be throttled
sub have_to_throttle {
    my ($self, $env) = @_;

    any { $env->{PATH_INFO} =~ /$_/ } @{ $self->routes };
}

#
# Checks if the requester's IP in the blacklist
sub is_remote_blacklisted {
    my ($self, $env) = @_;

    $self->_is_listed_in(blacklist => $env);
}

#
# Checks if the requester's IP in the whitelist
sub is_remote_whitelisted {
    my ($self, $env) = @_;

    $self->_is_listed_in(whitelist => $env);
}

#
# Checks if remote IP address in accesslist
sub _is_listed_in {
    my ($self, $list, $env) = @_;

    return unless $self->$list;
    return $self->$list->find($env->{REMOTE_ADDR});
}

#
# Populates the blacklist/whitelist
sub _initialize_accesslist {
    my ($self, $items) = @_;

    my $list = Net::CIDR::Lite->new;

    if ($items) {
        map { $list->add_any($_) } reftype($items) eq 'ARRAY' ? @$items : ( $items );
    }

    $list;
}

#
# Check if limits is not exceeded
sub is_allowed {
    my ($self) = @_;

    if (($self->backend->reqs_done < $self->backend->reqs_max) || $self->privileged) {
        $self->backend->increment;
        return $self->privileged
            ? 1 : $self->backend->reqs_done <= $self->backend->reqs_max ? 1 : 0;
    }
    else {
        return 0;
    }
}

#
# Requester's ID
sub requester_id {
    my ($self, $env) = @_;
    join ':' => 'throttle', $env->{REMOTE_ADDR}, ($env->{REMOTE_USER} || 'nobody');
}

1; # End of Plack::Middleware::Throttle::Lite

__END__

=pod

=head1 NAME

Plack::Middleware::Throttle::Lite - Requests throttling for Plack

=head1 VERSION

version 0.01

=head1 DESCRIPTION

This middleware allows to restrict access to PSGI application based on requests per unit of time (hour/day at the moment).
Implemetation of the middleware inspired by L<Plack::Middleware::Throttle>.

=head2 FEATURES

=over 4

=item Blacklisting

Requests from specified IPs (including ranges) or CIDRs are rejects immediately with response B<503 Service Unavailable>.

=item Whitelisting

Requests from specified IPs (including ranges) or CIDRs allows to get an unlimited access to the application.

=item Flexible and simple throttling policy

Access to an application might be configured on either by hourly or by daily basis.

=item Routes configuration

Flexible settings for routes matching based on regular expressions.

=item Various storage backends

There is an API which allows to write and use any database or cache system to manipulate throttling data.

=item Very lightweight

It will not install C<a-half-of-CPAN> or C<heavy> dependencies!

=back

=head1 SYNOPSYS

    # inside your app.psgi
    my $app = builder {
        enable 'Throttle::Lite',
            limits => '100 req/hour', backend => 'Simple',
            routes => [ qr{^/(host|item)/search}, qr{^/users/add} ],
            blacklist => [ '127.0.0.9/32', '10.90.90.90-10.90.90.92', '8.8.8.8', '192.168.0.10/31' ];
        sub {
            [ 200, ['Content-Type' => 'text/plain'], [ 'OK' ] ];
        }
    };

=head1 CONFIGURATION OPTIONS

=head2 limits

By this option is defined the throttling policy. At the moment, there are two variants in limiting of requests:
C<per hour> and C<per day>. Value of maximum requests might be pointed as number and measuring units (hour, day).
Some examples:

    # restrict to 520 request in an hour
    enable 'Throttle::Lite', limits => '520 req/hour';
    # ..maybe 10000 requests in a day?
    enable 'Throttle::Lite', limits => '10000 req/day';

Also valid more short constructions:

    # should not exceed 315 request in an hour
    enable 'Throttle::Lite', limits => '315 r/h';
    # ..19999 requests in a day
    enable 'Throttle::Lite', limits => '19999 r/d';

Or even

    # ..it works
    enable 'Throttle::Lite', limits => '51 req per hour';
    # ..this one also okay
    enable 'Throttle::Lite', limits => '99 r per d';
    # ..and this
    enable 'Throttle::Lite', limits => '72 r per hour';
    # ..no space between number and units also allowed
    enable 'Throttle::Lite', limits => '34r/hour';
    # ..oops! and this one does not work, yet ;-) sorry..
    enable 'Throttle::Lite', limits => '100rph';

If this option is omitted, there are some defaults will be assigned. For maximum requests default value will be B<199>
and measuring units - B<req/hour>. So this option must be set to desired value to have get correct throttling policy.

=head2 backend

Storage backend and its configuration options. Accepted values either string or list reference contains backend name and
options as hash reference. Backend name can be pointed in short module name or in fully qualified module name. If
module name does not belongs to B<Plack::Middleware::Throttle::Lite::Backend> namespace it can be pointed by adding B<+> (plus)
sign before name.

    # means Plack::Middleware::Throttle::Lite::Backend::Simple
    enable 'Throttle::Lite', backend => 'Simple';

    # means Plack::Middleware::Throttle::Lite::Backend::OwnStore
    enable 'Throttle::Lite', backend => 'OwnStore';

    # means My::Own::Throttle::Backend
    enable 'Throttle::Lite', backend => '+My::Own::Throttle::Backend';

If backend name passed as list reference, the first element will be handle as backend module and the second as options
passed to constructor during initialization.

    # treat as Plack::Middleware::Throttle::Lite::Backend::Anything
    enable 'Throttle::Lite',
        backend => [
            'Anything' => { server => 'anything.example.com', port => 23250 }
        ];
    # ..as My::Own::Any
    enable 'Throttle::Lite',
        backend => [
            '+My::Own::Any' => { server => 'anything.example.com', port => 23250 }
        ];

If no B<backend> specified then will be used in-memory backend L<Plack::Middleware::Throttle::Lite::Backend::Simple>
shipped with this distribution.

=head2 routes

URL pattern to match request to throttle. Accepted values are scalar (e.g. C</api>), regex (C<qr{^/(host|item)/search}>)
or a list reference with scalar/regex elements. Below some examples:

    # passing routes as scalar..
    enable 'Throttle::Lite',
        routes => '/api';

    # ..as regex
    enable 'Throttle::Lite',
        routes => qr{^/api/(user|host)};

    # ..shaken, not stirred
    enable 'Throttle::Lite',
        routes => [
            '/foo/bar',
            qr{^/(host|item)s/search},
            qr{^/users/add},
            qr{^/Api/Login}i,
            '/knock/knock',
        ];

All requests will be passed through (won't be handled by this middleware) if no routes given.

=head2 blacklist

Blacklist is aimed to restrict some bad guys to have get access to application which uses this middleware.
IP addresses can be passed either as string or as list of strings in a different forms. It might be simple IP address
(quad-dotted notation), IP block in CIDR notation or range of IP addresses (delimited by a hyphen).

    # passing IP address as string..
    enable 'Throttle::Lite',
        blacklist => '127.0.0.1';

    # ..as CIDR block
    enable 'Throttle::Lite',
        blacklist => '192.168.10.0/27';

    # ..as a range of IPs
    enable 'Throttle::Lite',
        blacklist => '10.90.90.90-10.90.90.92';

    # ..stirred, not shaken
    enable 'Throttle::Lite',
        blacklist => [
            '192.168.1.12/32',
            '10.90.90.90-10.90.90.92',
            '127.0.0.1',
            '10.104.32.64/29',
        ];

More details in L<Net::CIDR::Lite>.

B<Warning!> Blacklist has higher priority than L</whitelist>.

=head2 whitelist

Whitelist is aimed to grant some good guys to have get access to application which uses this middleware. Whitelisted
client's IP address will receive unlimited access to application. In generated header which is pointed to maximum requests
for whitelisted guy will be I<unlimited> instead of actually given maximum requests.

Rules of configuration IP addresses for whitelist the same as for the L</blacklist>.

B<Warning!> Whitelist has lower priority than L</blacklist>. Be sure that IP does not exists in blacklist by adding IP
to whitelist.

=head1 METHODS

=head2 prepare_app

See L<Plack::Middleware>

=head2 call

See L<Plack::Middleware>

=head2 modify_headers

Adds extra headers to each throttled response such as maximum requests (B<X-Throttle-Lite-Limit>),
measuring units (B<X-Throttle-Lite-Units>), requests done (B<X-Throttle-Lite-Used>). If maximum requests is equal to
requests done B<X-Throttle-Lite-Expire> header will appears.

=head2 reject_request

Rejects incoming request with specific code and reason. It might be either request from blacklisted IP or throttled one.

=head2 have_to_throttle

Checks if requested PATH_INFO matches the routes list and should be throttled.

=head2 is_remote_blacklisted

Checks if the requester's IP exists in the blacklist.

=head2 is_remote_whitelisted

Checks if the requester's IP exists in the whitelist.

=head2 is_allowed

Checks if client is not exceeded maximum allowed requests.

=head2 requester_id

Builds unique (as possible) indentificator of the client based on its IP address and name.

=head1 BUGS

Please report any bugs or feature requests through the web interface at
L<https://github.com/Wu-Wu/Plack-Middleware-Throttle-Lite/issues>

=head1 SEE ALSO

L<Plack>

L<Plack::Middleware>

=head1 AUTHOR

Anton Gerasimov <chim@cpan.org>

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2013 by Anton Gerasimov.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut
