package OpenSSL::safe::installdata;

use strict;
use warnings;
use Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(
    @PREFIX
    @libdir
    @BINDIR @BINDIR_REL_PREFIX
    @LIBDIR @LIBDIR_REL_PREFIX
    @INCLUDEDIR @INCLUDEDIR_REL_PREFIX
    @APPLINKDIR @APPLINKDIR_REL_PREFIX
    @ENGINESDIR @ENGINESDIR_REL_LIBDIR
    @MODULESDIR @MODULESDIR_REL_LIBDIR
    @PKGCONFIGDIR @PKGCONFIGDIR_REL_LIBDIR
    @CMAKECONFIGDIR @CMAKECONFIGDIR_REL_LIBDIR
    $VERSION @LDLIBS
);

our @PREFIX                     = ( '/media/bdg/GoldenGoose/OblivionsEdge/oblivion_webserver/openssl-3.5.0' );
our @libdir                     = ( '/media/bdg/GoldenGoose/OblivionsEdge/oblivion_webserver/openssl-3.5.0' );
our @BINDIR                     = ( '/media/bdg/GoldenGoose/OblivionsEdge/oblivion_webserver/openssl-3.5.0/apps' );
our @BINDIR_REL_PREFIX          = ( 'apps' );
our @LIBDIR                     = ( '/media/bdg/GoldenGoose/OblivionsEdge/oblivion_webserver/openssl-3.5.0' );
our @LIBDIR_REL_PREFIX          = ( '' );
our @INCLUDEDIR                 = ( '/media/bdg/GoldenGoose/OblivionsEdge/oblivion_webserver/openssl-3.5.0/include', '/media/bdg/GoldenGoose/OblivionsEdge/oblivion_webserver/openssl-3.5.0/include' );
our @INCLUDEDIR_REL_PREFIX      = ( 'include', './include' );
our @APPLINKDIR                 = ( '/media/bdg/GoldenGoose/OblivionsEdge/oblivion_webserver/openssl-3.5.0/ms' );
our @APPLINKDIR_REL_PREFIX      = ( 'ms' );
our @ENGINESDIR                 = ( '/media/bdg/GoldenGoose/OblivionsEdge/oblivion_webserver/openssl-3.5.0/engines' );
our @ENGINESDIR_REL_LIBDIR      = ( 'engines' );
our @MODULESDIR                 = ( '/media/bdg/GoldenGoose/OblivionsEdge/oblivion_webserver/openssl-3.5.0/providers' );
our @MODULESDIR_REL_LIBDIR      = ( 'providers' );
our @PKGCONFIGDIR               = ( '/media/bdg/GoldenGoose/OblivionsEdge/oblivion_webserver/openssl-3.5.0' );
our @PKGCONFIGDIR_REL_LIBDIR    = ( '.' );
our @CMAKECONFIGDIR             = ( '/media/bdg/GoldenGoose/OblivionsEdge/oblivion_webserver/openssl-3.5.0' );
our @CMAKECONFIGDIR_REL_LIBDIR  = ( '.' );
our $VERSION                    = '3.5.0';
our @LDLIBS                     =
    # Unix and Windows use space separation, VMS uses comma separation
    $^O eq 'VMS'
    ? split(/ *, */, '-ldl -pthread ')
    : split(/ +/, '-ldl -pthread ');

1;
