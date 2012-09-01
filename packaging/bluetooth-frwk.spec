Name:       bluetooth-frwk
Summary:    Bluetooth framework for BlueZ and Obexd. This package is Bluetooth framework based on BlueZ and Obexd stack.
Version:    0.1.85
Release:    1
Group:      TO_BE/FILLED_IN
License:    TO BE FILLED IN
Source0:    %{name}-%{version}.tar.gz

BuildRequires:  pkgconfig(aul)
BuildRequires:  pkgconfig(contacts-service)
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(syspopup-caller)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(libxml-2.0)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(utilX)
BuildRequires:  pkgconfig(msg-service)
BuildRequires:  pkgconfig(email-service)
BuildRequires:  pkgconfig(appcore-efl)
BuildRequires:  pkgconfig(appsvc)
BuildRequires:  cmake

Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description
Bluetooth framework for BlueZ and Obexd. This package is Bluetooth framework based on BlueZ and Obexd stack.
 This package contains API set for BT GAP, BT SDP, and BT RFCOMM.


%package devel
Summary:    Bluetooth framework for BlueZ and Obexd
Group:      TO_BE/FILLED
Requires:   %{name} = %{version}-%{release}

%description devel
This package is development files for Bluetooth framework based on BlueZ and Obexd stack.
This package contains API set for BT GAP, BT SDP, and BT RFCOMM.


%package agent
Summary:    Bluetooth Agent for pairing and authorization
Group:      TO_BE/FILLED
Requires:   %{name} = %{version}-%{release}

%description agent
This package is Bluetooth useraction Agent to response pairing, authorization, and mode change with BlueZ.

%prep
%setup -q


%build
export CFLAGS+=" -fpie"
export LDFLAGS+=" -Wl,--rpath=/usr/lib -Wl,--as-needed -Wl,--unresolved-symbols=ignore-in-shared-libs -pie"

cmake . -DCMAKE_INSTALL_PREFIX=/usr

make

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}%{_sysconfdir}/rc.d/rc3.d/
mkdir -p %{buildroot}%{_sysconfdir}/rc.d/rc5.d/
ln -s %{_sysconfdir}/rc.d/init.d/bluetooth-frwk-agent %{buildroot}%{_sysconfdir}/rc.d/rc3.d/S80bluetooth-frwk-agent
ln -s %{_sysconfdir}/rc.d/init.d/bluetooth-frwk-agent %{buildroot}%{_sysconfdir}/rc.d/rc5.d/S80bluetooth-frwk-agent

%post
vconftool set -t int db/bluetooth/status "0" -g 6520
vconftool set -t int memory/private/libbluetooth-frwk-0/obex_no_agent "0" -g 6520 -i
vconftool set -t string memory/private/libbluetooth-frwk-0/uuid "" -g 6520 -i
vconftool set -t string memory/bluetooth/sco_headset_name "" -g 6520 -i

%postun -p /sbin/ldconfig

%files
%defattr(-, root, root)
%{_libdir}/libbluetooth-api.so.*
%{_libdir}/libbluetooth-media-control.so.*
%{_libdir}/libbluetooth-telephony.so.*

%files devel
%defattr(-, root, root)
%{_includedir}/bluetooth-media-control/bluetooth-media-control.h
%{_includedir}/bluetooth-api/bluetooth-hid-api.h
%{_includedir}/bluetooth-api/bluetooth-audio-api.h
%{_includedir}/bluetooth-api/bluetooth-control-api.h
%{_includedir}/bluetooth-api/bluetooth-api.h
%{_includedir}/bluetooth-telephony/bluetooth-telephony-api.h
%{_libdir}/pkgconfig/bluetooth-media-control.pc
%{_libdir}/pkgconfig/bluetooth-api.pc
%{_libdir}/pkgconfig/bluetooth-telephony.pc
%{_libdir}/libbluetooth-api.so
%{_libdir}/libbluetooth-media-control.so
%{_libdir}/libbluetooth-telephony.so


%files agent
%defattr(-, root, root)
%{_sysconfdir}/rc.d/init.d/bluetooth-frwk-agent
%{_sysconfdir}/rc.d/rc3.d/S80bluetooth-frwk-agent
%{_sysconfdir}/rc.d/rc5.d/S80bluetooth-frwk-agent
%{_datadir}/dbus-1/services/org.bluez.pb_agent.service
%{_datadir}/dbus-1/services/org.bluez.frwk_agent.service
%{_datadir}/dbus-1/services/org.bluez.map_agent.service
%{_datadir}/dbus-1/services/org.bluez.hfp_agent.service
%{_bindir}/bluetooth-agent
%{_bindir}/bluetooth-map-agent
%{_bindir}/bluetooth-pb-agent
%{_bindir}/bluetooth-hfp-agent

