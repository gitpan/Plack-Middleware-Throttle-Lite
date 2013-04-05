use strict;
use warnings;
use feature ':5.10';
use Plack::Builder;
use Plack::Request;
use Plack::Response;
use lib qw(lib ../lib);

=pod

=head1 SYNOPSYS

    % plackup app-blacklist.psgi

=head1 THROTTLE-FREE REQUESTS

    % curl -v http://localhost:5000/foo/bar

No B<X-Throttle-Lite-*> headers will be displayed. Only content like

    Throttle-free request

=head1 THROTTLED REQUESTS

    % curl -v http://localhost:5000/api/user
    % curl -v http://localhost:5000/api/host

Headers B<X-Throttle-Lite-*> won't be displayed because of any remote address blacklisted. Response code is

    HTTP/1.0 403 Forbidden

Content like

    IP Address Blacklisted

=cut

builder {
    enable 'Throttle::Lite',
        limits => '5 req/hour', backend => 'Simple', routes => qr{^/api}i,
        blacklist => [ '0.0.0.0/0' ];
    sub {
        my ($env) = @_;
        my $body;

        given (Plack::Request->new($env)->path_info) {
            when (qr{^/api/(user|host)}i) { $body = 'API: ' . ucfirst($1)   }
            default                       { $body = 'Throttle-free request' }
        }

        Plack::Response->new(200, ['Content-Type' => 'text/plain'], $body)->finalize;
    };
};
