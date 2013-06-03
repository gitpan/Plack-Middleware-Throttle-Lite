use strict;
use warnings;
use Plack::Test;
use Plack::Builder;
use HTTP::Request::Common;
use Test::More;
use t::lib::PMTL;

my $app = sub {
    my ($units) = @_;

    builder {
        enable 'Throttle::Lite',
            limits => '2 ' . $units, backend => 'Simple', routes => '/api/user';
        t::lib::PMTL::get_app();
    };
};

my @samples = (
    #   code  limit used    expire     content              mime
    1,  200,  2,    1,      '',     'OK',              'text/html',
    2,  200,  2,    2,      '1',    'OK',              'text/html',
    3,  429,  2,    2,      '1',    'Limit Exceeded',  'text/plain',
);

# testing against all available limits
foreach my $units (qw(req/min req/hour req/day)) {
    test_psgi $app->($units), sub {
        my ($cb) = @_;

        while (my ($num, $code, $limit, $used, $expire_in, $content, $type) = splice(@samples, 0, 7)) {
            my $reqno = 'Request (' . $num . ') [' . $units . ']';
            my $res = $cb->(GET '/api/user/login');
            is $res->code,                                  $code,          $reqno . ' code';
            is $res->header('X-Throttle-Lite-Units'),       $units,         $reqno . ' units header';
            is $res->header('X-Throttle-Lite-Limit'),       $limit,         $reqno . ' limit header';
            is $res->header('X-Throttle-Lite-Used'),        $used,          $reqno . ' used header';
            is !!$res->header('X-Throttle-Lite-Expire'),    $expire_in,     $reqno . ' expire-in header';
            is !!$res->header('Retry-After'),               $expire_in,     $reqno . ' retry-after header';
            like $res->content,                             qr/$content/,   $reqno . ' content';
            is $res->content_type,                          $type,          $reqno . ' content type';
        }
    };
}

done_testing();
