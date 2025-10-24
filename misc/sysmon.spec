Summary: System Monitoring Daemon
Version: 0.92.1
Name: sysmon
URL: http://puck.nether.net/sysmon/
Packager: jared@puck.nether.net
Release: 1
Group: Applications/System
Copyright: 2004 Jared Mauch
Source0: %{name}-%{version}.tar.gz
Source1: sysmond.init
BuildRoot: /var/tmp/%{name}-buildroot

%description
Sysmon is a network monitoring tool designed to provide high performance and
accurate network monitoring. Currently supported protocols include SMTP, IMAP,
HTTP, TCP, UDP, NNTP, and PING tests.

%prep
%setup
%configure --prefix=/usr
%build
make

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT/etc/rc.d/init.d
install -d $RPM_BUILD_ROOT/usr/bin
install -d $RPM_BUILD_ROOT/usr/sbin
install -d $RPM_BUILD_ROOT/usr/man/man5
install -d $RPM_BUILD_ROOT/usr/man/man8
install src/sysmon $RPM_BUILD_ROOT/usr/bin
install src/sysmond $RPM_BUILD_ROOT/usr/sbin
install docs/sysmon.man $RPM_BUILD_ROOT/usr/man/man8/sysmon.8
install docs/sysmon.conf.man $RPM_BUILD_ROOT/usr/man/man5/sysmon.conf.5
install %{SOURCE1} $RPM_BUILD_ROOT/etc/rc.d/init.d/sysmond

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc LICENSE WISHLIST docs/[A-Z]* docs/*.jpg docs/*.html examples
%attr(755,root,root) /etc/rc.d/init.d/sysmond
%attr(711,root,root) /usr/bin/sysmon
%attr(700,root,root) /usr/sbin/sysmond
%attr(644,root,man) /usr/man/man8/sysmon.8*
%attr(644,root,man) /usr/man/man5/sysmon.conf.5*

%post
/sbin/chkconfig --add sysmond

%preun
/sbin/chkconfig --del sysmond
