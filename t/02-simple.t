use strict;
use warnings;
use Plack::Test;
use Plack::Builder;
use HTTP::Request::Common;
use Test::More;
use Plack::Middleware::Throttle::Lite::Backend::Simple;

can_ok 'Plack::Middleware::Throttle::Lite::Backend::Simple', qw(
    increment
    reqs_done
    reqs_max
    units
    settings
    expire_in
    cache_key
    ymdh
);

# simple application
my $app = sub {
    [
        200,
        [ 'Content-Type' => 'text/html' ],
        [ '<html><body>OK</body></html>' ]
    ];
};

my $app1 = builder {
    enable 'Throttle::Lite',
        limits => '5 req/hour', backend => 'Simple', routes => '/api/user',
        blacklist => [ '127.0.0.9/32', '10.90.90.90-10.90.90.92', '8.8.8.8', '192.168.0.10/31' ];
    $app;
};

my @samples = (
    #   code  used    expire     content              mime
    1,  200,    1,      '',     'OK',              'text/html',
    2,  200,    2,      '',     'OK',              'text/html',
    3,  200,    3,      '',     'OK',              'text/html',
    4,  200,    4,      '',     'OK',              'text/html',
    5,  200,    5,      '1',    'OK',              'text/html',
    6,  503,    5,      '1',    'Limit exceeded',  'text/plain',
    7,  503,    5,      '1',    'Limit exceeded',  'text/plain',
);

test_psgi $app1, sub {
    my ($cb) = @_;

    while (my ($num, $code, $used, $expire_in, $content, $type) = splice(@samples, 0, 6)) {
        my $reqno = 'Request (' . $num . ')';
        my $res = $cb->(GET '/api/user/login');
        is $res->code,                                      $code,          $reqno . ' code';
        is $res->header('X-Throttle-Lite-Used'),            $used,          $reqno . ' used header';
        is defined($res->header('X-Throttle-Lite-Expire')), $expire_in,     $reqno . ' expire-in header';
        like $res->content,                                 qr/$content/,   $reqno . ' content';
        is $res->content_type,                              $type,          $reqno . ' content type';
    }
};

#
# Fake REMOTE_ADDR with whitelist feature
#
my %ips = (
    '192.168.0.2'  => [
        #   code  used   limit      expire   content              mime
        1,  200,    1,    2,          '',     'OK',              'text/html',
        2,  200,    2,    2,         '1',     'OK',              'text/html',
        3,  503,    2,    2,         '1',     'Limit exceeded',  'text/plain',
    ],
    '10.104.52.18' => [
        #   code  used   limit       expire  content              mime
        1,  200,    1,  'unlimited',  '',     'OK',              'text/html',
        2,  200,    2,  'unlimited',  '',     'OK',              'text/html',
        3,  200,    3,  'unlimited',  '',     'OK',              'text/html',
    ],
);

my $app2 = builder {
    enable 'Throttle::Lite',
        limits => '2 req/hour', backend => 'Simple', routes => '/api/user', whitelist => [ '10.104.52.0/27' ];
    $app;
};

foreach my $ipaddr (keys %ips) {
    my $appz = builder {
        enable sub { my ($app) = @_; sub { my ($env) = @_; $env->{REMOTE_ADDR} = $ipaddr; $app->($env) } };
        $app2;
    };

    while (my ($num, $code, $used, $limit, $expire_in, $content, $type) = splice(@{ $ips{$ipaddr} }, 0, 7)) {
        test_psgi $appz, sub {
            my ($cb) = @_;

            my $reqno = 'Request (' . $num . ') [' . $ipaddr . ']';
            my $res = $cb->(GET '/api/user/login');

            is $res->code,                                      $code,          $reqno . ' code';
            is $res->header('X-Throttle-Lite-Used'),            $used,          $reqno . ' used header';
            is $res->header('X-Throttle-Lite-Limit'),           $limit,         $reqno . ' limit header';
            is defined($res->header('X-Throttle-Lite-Expire')), $expire_in,     $reqno . ' expire-in header';
            like $res->content,                                 qr/$content/,   $reqno . ' content';
            is $res->content_type,                              $type,          $reqno . ' content type';
        };
    }
}

#
# Fake REMOTE_ADDR + REMOTE_USER with whitelist feature
#
my %ip_user = (
        #   code  used   limit      expire   content              mime
    '10.13.100.221:ldap'  => [
        1,  200,    1,    2,          '',     'OK',              'text/html',
        2,  200,    2,    2,         '1',     'OK',              'text/html',
        3,  503,    2,    2,         '1',     'Limit exceeded',  'text/plain',
    ],
    '10.13.100.221:bind'  => [
        1,  200,    1,    2,          '',     'OK',              'text/html',
        2,  200,    2,    2,         '1',     'OK',              'text/html',
        3,  503,    2,    2,         '1',     'Limit exceeded',  'text/plain',
    ],
    '10.104.52.18:chim' => [
        1,  200,    1,  'unlimited',  '',     'OK',              'text/html',
        2,  200,    2,  'unlimited',  '',     'OK',              'text/html',
        3,  200,    3,  'unlimited',  '',     'OK',              'text/html',
    ],
    '10.104.52.18:root' => [
        1,  200,    1,  'unlimited',  '',     'OK',              'text/html',
        2,  200,    2,  'unlimited',  '',     'OK',              'text/html',
        3,  200,    3,  'unlimited',  '',     'OK',              'text/html',
    ],
);

foreach my $pair (keys %ip_user) {

    my $appx = builder {
        enable sub {
            my ($app) = @_;
            sub {
                my ($env) = @_;
                ($env->{REMOTE_ADDR}, $env->{REMOTE_USER}) = split /:/, $pair;
                $app->($env);
            };
        };
        $app2;
    };

    while (my ($num, $code, $used, $limit, $expire_in, $content, $type) = splice(@{ $ip_user{$pair} }, 0, 7)) {
        test_psgi $appx, sub {
            my ($cb) = @_;

            my $reqno = 'Request (' . $num . ') [' . $pair . ']';
            my $res = $cb->(GET '/api/user/login');

            is $res->code,                                      $code,          $reqno . ' code';
            is $res->header('X-Throttle-Lite-Used'),            $used,          $reqno . ' used header';
            is $res->header('X-Throttle-Lite-Limit'),           $limit,         $reqno . ' limit header';
            is defined($res->header('X-Throttle-Lite-Expire')), $expire_in,     $reqno . ' expire-in header';
            like $res->content,                                 qr/$content/,   $reqno . ' content';
            is $res->content_type,                              $type,          $reqno . ' content type';
        };
    }
}

done_testing();
