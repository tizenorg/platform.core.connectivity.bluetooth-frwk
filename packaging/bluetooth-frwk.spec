Name:       bluetooth-frwk
Summary:    Network Bluetooth Framework
Version:    0.2
Release:    1
Group:      Network & Connectivity/Bluetooth
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: %{name}.manifest

BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  pkgconfig(gio-unix-2.0)
BuildRequires:  pkgconfig(capi-base-common)
BuildRequires:  pkgconfig(notification)

BuildRequires:  cmake

%description
Network Bluetooth Framework, for embedded/mobile and desktop systems based on
Linux, containing features of BlueZ and Obexd.

%package test
Summary:    Test case for Bletooth Framework (DEV)
Requires:   %{name} = %{version}

%description test
Test case for Bluetooth Framework (DEV). Some test programs to test the APIs
and interfaces about Bluetooth Framework or other inner code.

%package devel
Summary:    Network Bluetooth Framework (DEV)
Requires:   %{name} = %{version}-%{release}

%description devel
Development files for Bleutooth Framework based on BlueZ an Obexd stack, with
API descriptions files and config file.

%prep
%setup -q
cp %{SOURCE1001} .

%build
MAJORVER=`echo %{version} | awk 'BEGIN {FS="."}{print $1}'`
%cmake . -DFULLVER=%{version} -DMAJORVER=${MAJORVER} -Dplatform=IVI

make %{?jobs:-j%jobs}

%install
%make_install

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%manifest %{name}.manifest
%defattr(-, root, root)
%{_bindir}/bluetooth-service
/usr/lib/bluetooth-service/plugins/bluetooth-ivi.so
%{_libdir}/libcapi-network-bluetooth.so.*
%config %{_sysconfdir}/dbus-1/system.d/bluezlib.conf
%config %{_sysconfdir}/dbus-1/system.d/bluezobex.conf
%config %{_sysconfdir}/dbus-1/system.d/bluetooth-service.conf
%{_datadir}/dbus-1/system-services/org.tizen.comms.service

%files test
%manifest %{name}.manifest
%{_libdir}/%{name}-test/bluez-capi-test
%{_libdir}/%{name}-test/bt-serivce-lib-test
%{_libdir}/%{name}-test/bluez-lib-test
%{_libdir}/%{name}-test/obex-lib-test
%{_libdir}/%{name}-test/test-perso
%config %{_sysconfdir}/dbus-1/system.d/bluez-lib-test.conf

%files devel
%{_includedir}/network/bluetooth.h
%{_libdir}/pkgconfig/capi-network-bluetooth.pc
%{_libdir}/libcapi-network-bluetooth.so
