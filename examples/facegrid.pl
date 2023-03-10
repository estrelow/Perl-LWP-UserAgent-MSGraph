#!/usr/bin/perl
#=====================================================================
#   facegrid.pl
#
#   msgraph sample script
#
#   THIS SCRIPT IS A SAMPLE TO SHOW MS GRAPH INTERACTION
#
#   Bult using Mojolicious framework
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#=====================================================================

use strict;
use warnings;

use constant APPID => 'a17907d1-8671-4ef5-a8c3-1561ee60e6a3';
use constant SECRET => 'kuo8Q~aTVe4GpGQKJ4s26QeqR2Hd2W2qw1FwIalK';
use constant TENANT => 'a68cc546-67a3-4b13-87f4-414e9e0b94ef';
use constant HTTP_HOME => "http://localhost:8081";

use constant MAX_FACES => 20;
use LWP::UserAgent::msgraph;

my $ms;

use Mojolicious::Lite -signatures;

under sub ($c) {

     my $sid=$c->param('session');
     
     #Here we create an MS Graph environment for every Mojo request
     #The persistent flag and session param allows to reuse the
     #same environment in further Mojo requests
     $ms=LWP::UserAgent::msgraph->new(
      appid => APPID,
      secret => SECRET,
      tenant => TENANT,
      grant_type=> 'authorization_code',
      scope => 'openid User.Read.All',
      redirect_uri=>HTTP_HOME."/auth",
      sid => $sid,
      persistent => 1  );
};

get '/' => sub ($c) {
   return $c->redirect_to($ms->authendpoint);
};

get '/auth' => sub($c) {
    $ms->auth($c->param('code'));
    my $sid=$ms->sid;
    my $viewer=$c->url_for("/view")->query(session=>$sid);
    return $c->redirect_to($viewer);
};

get '/view' => sub($c) {

   my $list=$ms->get('/users?$select=id,displayname&$filter=userType eq \'Member\'&$top='.MAX_FACES);

   my $s='';
   for (@{$list->{value}}) {
      $s= "$s ".$_->{displayName};
   }
   $c->render(template => 'default', grid => $s);
   
};


app->start('daemon','-l', HTTP_HOME);

__DATA__

@@default.html.ep
<!DOCTYPE html>
<html lang="en">
 <head>
  <meta charset="UTF-8">
  <meta name="Generator" content="EditPlus">
  <meta name="Author" content="">
  <meta name="Keywords" content="">
  <meta name="Description" content="">
  <title>Document</title>
 </head>
 <body>
  Hello world <%= $grid  %>
 </body>
</html>

