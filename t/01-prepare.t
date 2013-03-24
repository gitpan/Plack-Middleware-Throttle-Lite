use strict;
use warnings;
use Plack::Test;
use Plack::Builder;
use HTTP::Request::Common;
use Test::More;
use Plack::Middleware::Throttle::Lite;

can_ok 'Plack::Middleware::Throttle::Lite', qw(prepare_app call limits);

# simple application
my $app = sub {
    [
        200,
        [ 'Content-Type' => 'text/html' ],
        [ '<html><body>OK</body></html>' ]
    ];
};

#
# catch exception
#

eval { $app = builder { enable 'Throttle::Lite', backend => 'Bogus'; $app } };
like $@, qr|Can't locate Plack.*Bogus\.pm|, 'Unknown non-FQN backend exception';

eval { $app = builder { enable 'Throttle::Lite', backend => [ 'Bogus' => {} ]; $app } };
like $@, qr|Can't locate Plack.*Bogus\.pm|, 'Unknown non-FQN backend exception with options';

eval { $app = builder { enable 'Throttle::Lite', backend => '+My::Own::Bogus'; $app } };
like $@, qr|Can't locate My.*Bogus\.pm|, 'Unknown FQN backend exception';

eval { $app = builder { enable 'Throttle::Lite', backend => { 'Bogus' => {} }; $app } };
like $@, qr|Expected scalar or array reference|, 'Invalid backend configuration exception (hash ref)';

eval { $app = builder { enable 'Throttle::Lite', backend => (bless {}, 'Bogus'); $app } };
like $@, qr|Expected scalar or array reference|, 'Invalid backend configuration exception (blessed ref)';

eval { $app = builder { enable 'Throttle::Lite', routes => {}; $app } };
like $@, qr|Expected scalar, regex or array reference|, 'Invalid routes configuration exception (hash ref)';

eval { $app = builder { enable 'Throttle::Lite', routes => sub {}; $app } };
like $@, qr|Expected scalar, regex or array reference|, 'Invalid routes configuration exception (code ref)';

$app = builder {
    enable 'Throttle::Lite',
        limits => '100 req/hour', backend => 'Simple', routes => '/api/user',
        blacklist => [ '127.0.0.9/32', '10.90.90.90-10.90.90.92', '8.8.8.8', '192.168.0.10/31' ];
    $app;
};

#
# catch requsted path
#

my @prepare_tests = (
    (GET '/') => sub {
        is $_->code, 200;
        is $_->content, '<html><body>OK</body></html>';
        is $_->header('X-Throttle-Lite-Limit'), undef;
        is $_->header('X-Throttle-Lite-Units'), undef;
    },
    (GET '/api/user/login') => sub {
        is $_->code, 200;
        is $_->header('X-Throttle-Lite-Limit'), 100;
        is $_->header('X-Throttle-Lite-Units'), 'req/hour';
    },
    (GET '/api/host/delete') => sub {
        is $_->code, 200;
        is $_->header('X-Throttle-Lite-Limit'), undef;
        is $_->header('X-Throttle-Lite-Units'), undef;
    },
);

while (my ($req, $test) = splice(@prepare_tests, 0, 2) ) {
    test_psgi
        app => $app,
        client => sub {
            my ($cb) = @_;
            my $res = $cb->($req);
            local $_ = $res;
            $test->($res, $req);
        };
}

#
# blacklisting in action
#

my @ips = (
    '0.0.0.0'      => [ 200, 'OK'          ],
    '127.0.0.1'    => [ 200, 'OK'          ],
    '127.0.0.9'    => [ 503, 'blacklisted' ],
    '10.90.90.78'  => [ 200, 'OK'          ],
    '10.90.90.90'  => [ 503, 'blacklisted' ],
    '10.90.90.91'  => [ 503, 'blacklisted' ],
    '10.90.90.92'  => [ 503, 'blacklisted' ],
    '8.8.8.8'      => [ 503, 'blacklisted' ],
    '8.8.4.4'      => [ 200, 'OK'          ],
    '192.168.0.10' => [ 503, 'blacklisted' ],
    '192.168.0.11' => [ 503, 'blacklisted' ],
    '192.168.0.12' => [ 200, 'OK'          ],
);

while (my ($ipaddr, $resp) = splice(@ips, 0, 2)) {
    test_psgi
        app => builder {
            enable sub { my ($app) = @_; sub { my ($env) = @_; $env->{REMOTE_ADDR} = $ipaddr; $app->($env) } };
            $app;
        },
        client => sub {
            my ($cb) = @_;
            my $res = $cb->(GET '/api/user/login');
            is $res->code, $resp->[0], 'Valid code for request from ' . $ipaddr;
            like $res->content, qr/$resp->[1]/, 'Valid content for request from ' . $ipaddr;
        };
}

done_testing();
