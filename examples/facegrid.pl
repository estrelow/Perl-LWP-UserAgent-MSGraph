#!/usr/bin/perl
use strict;
use warnings;

use constant APPID => 'a17907d1-8671-4ef5-a8c3-1561ee60e6a3';
use constant SECRET => 'kuo8Q~aTVe4GpGQKJ4s26QeqR2Hd2W2qw1FwIalK';
use constant TENANT => 'a68cc546-67a3-4b13-87f4-414e9e0b94ef';
use constant HTTP_PORT => '8081';

use constant MAX_FACES => 20;
use LWP::UserAgent::msgraph;

my $ms;

use Mojolicious::Lite -signatures;

under sub ($c) {
     $ms=LWP::UserAgent::msgraph->new(
      appid => APPID,
      secret => SECRET,
      tenant => TENANT,
      grant_type=> 'authorization_code',
      scope => 'openid user.read profile',
      redirect_uri=>"http://localhost:".HTTP_PORT."/auth");
};

get '/' => sub ($c) {
   return $c->redirect_to($ms->authendpoint);
};

get '/auth' => sub($c) {
    $ms->auth($c->param('code'));
    my $sid=$ms->sid;
    return $c->redirect_to("view", session=>$sid);
};

get '/view' => sub($c) {

   $c->render(text => 'Hello world');
   
};


app->start('daemon','-l', "http://127.0.0.1:".HTTP_PORT);
