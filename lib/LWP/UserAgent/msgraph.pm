package LWP::UserAgent::msgraph;

use strict;
use warnings;

our $VERSION = '0.01';

use parent 'LWP::UserAgent';

use JSON;
use Storable;
use Data::UUID;
use File::Spec;
use Storable;
use Carp;
use HTTP::Request::Common;

sub new($%) {

   my %internals;

   my $class=shift();
   
   my %args=@_;

   #This are our lwp-extended options
   for (qw(appid secret auth grant_type scope persistent sid base store return_url)) {
      if (exists $args{$_}) {
         $internals{$_}= $args{$_};
         delete $args{$_};
      }
   }

   #Some defaults
   unless (exists $internals{sid}) {
      my $guid=Data::UUID->new;
      $internals{sid}=$guid->create_str();
   }

   my $sid=$internals{sid};

   $internals{base}='https://graph.microsoft.com/v1.0' unless(exists $internals{base}); 
   $internals{base} =~ s/\/$//;

   #complain about missing options
   for (qw(appid grant_type)) {
      croak "Missing mandatory option $_" unless (exists $internals{$_});
   }

   #Now the persistent thing
   $internals{persistent}=1 if (exists $internals{store} && ! exists $internals{persistent});
   $internals{persistent}=0 unless (exists $internals{persistent});

   if ($internals{persistent} && ! exists $internals{store}) {
      my $tmpdir = File::Spec->tmpdir();
      $internals{store}="$tmpdir/$sid.tmp";
   }

   if ($internals{persistent} && -r $internals{store}) {
      my $stored=retrieve($internals{store});
      croak 'Mismatch persistent session' unless ($stored->{sid} eq $sid);
      for (keys %$stored) {
         $internals{$_}=$stored->{$_};
      }
   }
   
   my $self=$class->SUPER::new(%args);
   for (keys %internals) {
      $self->{$_} = $internals{$_};
   }

   return $self;

}

sub writestore($) {
   
   my $self=shift();

   croak 'Wrong writestore call on non-persistant client' unless ($self->{persistent});

   my $data={};

   #This is a subset of the runtime data. It's important that the secret is out
   for (qw(access_token expires expires_in refresh_token token_type scope appid sid)) {
      $data->{$_}=$self->{$_};
   }
   return store $data, $self->{store};
}

sub request {

   my ($self,$method, $url, $payload)=@_;

   $url =~ s/^\///;

   my $abs_uri=URI->new_abs($url, $self->{base}.'/');

   my $req=HTTP::Request->new($method,"$abs_uri");
   $req->header('Content-Type' => 'application/json');
   $req->header('Accept' => 'application/json');
   $req->content(to_json($payload)) if ($payload);

   my $res=LWP::UserAgent::request($self,$req);

   $self->{code}=$res->code;

   if ($res->is_success) {
      my $data=from_json($res->decoded_content);
      if (exists $data->{'@odata.nextLink'}) {
         $self->{nextLink}=$data->{'@odata.nextLink'};
      } else {
         $self->{nextLink}=0;
      }
      return $data;
   } else {
      croak $res->decoded_content
   }
}

sub code($) {

   my $self=shift();
   return $self->{code};
}

sub next($) {

   my $self=shift();

   if ($self->{nextLink}) {
      return $self->request('GET' => $self->{nextLink});
   } else {
      return 0;
   }
}

sub auth {

   my $self=shift();

   #Client-credentials for user-less anonymous connection
   if ($self->{grant_type} eq 'client_credentials') {

      my $post=HTTP::Request::Common::POST($self->{auth},
         [client_id => $self->{appid},
          scope => 'https://graph.microsoft.com/.default',
          client_secret=> $self->{secret},
          grant_type => $self->{grant_type}
      ]);
      my $r=$self->simple_request($post);
      unless ($r->is_success) {
         croak "Authentication failure ".$r->decoded_content;
      }

      my $data=from_json($r->decoded_content);
      for (keys %$data) {
         $self->{$_}=$data->{$_};
      }

      $self->{expires}=(time + $data->{expires_in});
      $self->writestore() if ($self->{presistent});
      $self->default_header('Authorization' => "Bearer ".$self->{access_token});
     
      return $data->{access_token};
   }

}

sub get {

   my ($self,@params)=@_;

   return $self->request('GET',@params);
}

sub post {
   my ($self,@params)=@_;

   return $self->request('POST',@params);

}

sub head {
   my ($self,@params)=@_;

   return $self->request('HEAD',@params);

}

sub patch {
   my ($self,@params)=@_;

   return $self->request('PATCH',@params);

}

sub put {
   my ($self,@params)=@_;

   return $self->request('PUT',@params);

}

sub delete {
   my ($self,@params)=@_;

   return $self->request('DELETE',@params);

}

1;

=pod

=encoding UTF-8

=head1 NAME

LWP::UserAgent::msgraph

=head1 VERSION

version 0.01

=head1 SYNOPSIS

   use LWP::UserAgent::msgraph;

   #The XXXX, YYYY and ZZZZ are setup during the Azure App Registration
   #Application Permission version
   $ua = LWP::UserAgent::msgraph->new(
      appid => 'XXXX',
      secret => 'YYYY',
      auth => 'ZZZZ',
      grant_type => 'client_credentials');
   $joe=$ua->request(GET => '/users/jdoe@some.com');
   $dn=$joe->{displayName};

=head1 DESCRIPTION  

This module allows the interaction between Perl and the MS Graph API service.
Therefore, a MS Graph application can be built using Perl. The application must
be correctly registered within Azure with the proper persmissions.

=head1 CONSTRUCTOR

   my $ua=LWP::UserAgent->new(%options);

This method constructs a new L<LWP::UserAgent::msgraph> object.
key/value pairs must be supplied in order to setup the object
properly. Missing mandatory options will result in error

   KEY              MEANING
   -------          -----------------------------------
   appid            Application (client) ID
   secret           shared secret needed for handshake
   auth             URL for oAuth 2.0 token endpoint
   grant_type       Authorizations scheme (client_credentials,authorization_code)

=head1 request

   my $object=$ua->request(GET => '/me');
   $ua->request(PATCH => '/me', {officeLocation => $mynewoffice});

The request method makes a call to a MS Graph endpoint url and returns the
corresponding response object. An optional perl structure might be
supplied as the payload (body) for the request.

The MS Graph has a rich set of API calls for different operations. Check the
L<EXAMPLES> section for more tips.

=head1 code

   print "It worked" if ($ua->code == 201);

A code() method is supplied as a convenient way of getting the last HTTP response
code.

=head1 next

   $more=$ua->next();

The next() method will request additional response content after a previous
request if a pagination result set happens.

=head1 Changes from the default L<LWP::UserAgent> behavior

The L<request> now accepts a perl structure which will be sent 
as a JSON body to the MS Graph endoint. Instead of an L<HTTP::Respones>
object, request() will return whatever object is returned by the
MS Graph method, as a perl structure. The <JSON> module is used as
a serialization engine.

request() will use the right Authorization header based on the initial handshake.
The get(), post(), patch(), delete(), put(), delete() methods are setup so
they call the LWP::UserAgent::msgraph version of request(). That is, they would
return a perl structure according to the MS Graph method. 
In particular, post() and patch() accepts a perl structure
as the body. All the binding with the L<HTTP::Request::Common> module has been broken.

The simple_request() method is kept unchanged, but will use the
right Bearer token authentication. So, if you need more control over the request, you can use
this method. You must add the JSON serialization, though.



=cut
