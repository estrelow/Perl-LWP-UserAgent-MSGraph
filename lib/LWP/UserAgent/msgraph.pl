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

   my $abs_uri=URI->new_abs($url, $self->{base});

   my $req=HTTP::Request->new($method,"$abs_uri");
   $req->header('Authorization' => "Bearer ".$self->{access_token});
   $req->header('Content-Type' => 'application/json');
   $req->header('Accept' => 'application/json');
   $req->content(to_json($payload)) if ($payload);

   my $res=SUPER::request($self,$req);

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
      my $r=$self->post($self->{auth},
         [client_id => $self->{appid},
          scope => 'https://graph.microsoft.com/.default',
          client_secret=> $self->{secret},
          grant_type => $self->{grant_type}
      ]);

      unless ($r->is_success) {
         croak "Authentication failure ".$r->decoded_content;
      }

      my $data=from_json($r->decoded_content);
      for (keys %$data) {
         $self->{$_}=$data->{$_};

      }

      $self->{expires}=(time + $data->{expires_in});
      $self->writestore() if ($self->{presistent});
      
      return $data->{access_token};
   }

}

1;

