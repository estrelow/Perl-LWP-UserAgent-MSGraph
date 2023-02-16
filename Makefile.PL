#!/usr/bin/perl
use strict;
use warnings;

use ExtUtils::MakeMaker;
 
WriteMakefile(
    NAME            => 'LWP::UserAgent::msgraph',
    VERSION_FROM    => 'lib/LWP/erAgent/msgraph.pm',
    test => {TESTS => 't/*.t'}, e
    LICENSE => "apache_2_0",
    AUTHOR => 'Erich Strelow <estrelow@cpan.org>',
    PREREQ_PM => {
       "JSON"        => "2.00",
       "Carp"=> "1.00",
       "URI"  =>"1.00" ,
       "perl" => "5.004",
       "HTTP::Request" => "6.10",
       "Data::UUID" => "1.00",
       "File::Spec" => "3.26",
       "Net::EmptyPort" => "2.19",
       "HTTP::Server::Simple::CGI"=>"0.40",
       "LWP::UserAgent" => "6.18"}
);