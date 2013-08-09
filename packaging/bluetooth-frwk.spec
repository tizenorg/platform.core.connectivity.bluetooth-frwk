%bcond_with bluetooth_frwk_libnotify
Name:       bluetooth-frwk
Summary:    Bluetooth framework for BlueZ and Obexd
Version:    0.2.57
Release:    1
Group:      Connectivity/Bluetooth
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: bluetooth-frwk.manifest
Source1002: bt-icon.png
URL:        https://review.tizen.org/git/?p=platform/core/connectivity/bluetooth-frwk.git;a=summary
Requires: dbus
Requires: syspopup
Requires:bluetooth-tools
BuildRequires:  pkgconfig(aul)
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(glib-2.0)
%if %{with bluetooth_frwk_libnotify}
BuildRequires:  pkgconfig(libnotify)
BuildRequires:  pkgconfig(gdk-pixbuf-2.0)
BuildRequires:  pkgconfig(gtk+-3.0)
%else
BuildRequires:  pkgconfig(syspopup-caller)
%endif
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(libxml-2.0)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(utilX)
BuildRequires:  pkgconfig(capi-network-tethering)
BuildRequires:  pkgconfig(libprivilege-control)
BuildRequires:  pkgconfig(status)
BuildRequires:  pkgconfig(alarm-service)
BuildRequires:  pkgconfig(notification)
BuildRequires:  pkgconfig(security-server)
BuildRequires:  cmake

Requires(post): vconf
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description
Bluetooth framework for BlueZ and Obexd. This package is Bluetooth framework based on BlueZ and Obexd stack.
 This package contains API set for BT GAP, BT SDP, and BT RFCOMM.


%package devel
Summary:    Bluetooth framework for BlueZ and Obexd
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
This package is development files for Bluetooth framework based on BlueZ and Obexd stack.
This package contains API set for BT GAP, BT SDP, and BT RFCOMM.

%package service
Summary:    Bluetooth Service daemon
Group:      Connectivity/Bluetooth
Requires:   %{name} = %{version}-%{release}

%description service
This package is Bluetooth Service daemon to manage BT services.

%package core
Summary:    Bluetooth Core daemon
Group:      Connectivity/Bluetooth
Requires:   %{name} = %{version}-%{release}

%description core
This package is Bluetooth core daemon to manage activation / deactivation.

%prep
%setup -q
cp %{SOURCE1001} .


%build

%ifarch x86_64
export CFLAGS+="   -Wall -g -fvisibility=hidden -fPIC"
export LDFLAGS+=" -Wl,--rpath=%{_libdir} -Wl,--as-needed -Wl,--unresolved-symbols=ignore-in-shared-libs" 
%else
export CFLAGS+=" -fpie"
export LDFLAGS+=" -Wl,--rpath=%{_libdir} -Wl,--as-needed -Wl,--unresolved-symbols=ignore-in-shared-libs -pie"
%endif
%cmake . \
%if %{with bluetooth_frwk_libnotify}
 -DLIBNOTIFY_SUPPORT=On
%else
 -DLIBNOTIFY_SUPPORT=Off
%endif

make

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}%{_sysconfdir}/rc.d/rc3.d/
mkdir -p %{buildroot}%{_sysconfdir}/rc.d/rc5.d/
ln -s %{_sysconfdir}/rc.d/init.d/bluetooth-frwk-service %{buildroot}%{_sysconfdir}/rc.d/rc3.d/S80bluetooth-frwk-service
ln -s %{_sysconfdir}/rc.d/init.d/bluetooth-frwk-service %{buildroot}%{_sysconfdir}/rc.d/rc5.d/S80bluetooth-frwk-service

mkdir -p %{buildroot}%{_unitdir_user}
mkdir -p %{buildroot}%{_unitdir_user}/tizen-middleware.target.wants
install -m 0644 bt-service/bluetooth-frwk-service.service %{buildroot}%{_unitdir_user}
ln -s ../bluetooth-frwk-service.service %{buildroot}%{_unitdir_user}/tizen-middleware.target.wants/bluetooth-frwk-service.service

%if %{with bluetooth_frwk_libnotify}
mkdir -p %{buildroot}%{_datadir}/icons/default
install -m 0644 %{SOURCE1002} %{buildroot}%{_datadir}/icons/default/bt-icon.png
%endif

%post
/sbin/ldconfig
vconftool set -tf int db/bluetooth/status "0" -g 6520
vconftool set -tf int file/private/bt-service/flight_mode_deactivated "0" -g 6520 -i
vconftool set -tf string memory/bluetooth/sco_headset_name "" -g 6520 -i
vconftool set -tf int memory/bluetooth/device "0" -g 6520 -i
vconftool set -tf int memory/bluetooth/btsco "0" -g 6520 -i

%postun -p /sbin/ldconfig

%files
%manifest %{name}.manifest
%defattr(-, root, root)
%{_libdir}/libbluetooth-api.so.*

%files devel
%manifest %{name}.manifest
%defattr(-, root, root)
%{_includedir}/bt-service/bluetooth-api.h
%{_includedir}/bt-service/bluetooth-hid-api.h
%{_includedir}/bt-service/bluetooth-audio-api.h
%{_includedir}/bt-service/bluetooth-telephony-api.h
%{_includedir}/bt-service/bluetooth-media-control.h
%{_libdir}/pkgconfig/bluetooth-api.pc
%{_libdir}/libbluetooth-api.so

%files service
%manifest %{name}.manifest
%defattr(-, root, root)
%{_sysconfdir}/rc.d/init.d/bluetooth-frwk-service
%{_sysconfdir}/rc.d/rc3.d/S80bluetooth-frwk-service
%{_sysconfdir}/rc.d/rc5.d/S80bluetooth-frwk-service
%{_datadir}/dbus-1/system-services/org.projectx.bt.service
%{_bindir}/bt-service
%{_unitdir_user}/tizen-middleware.target.wants/bluetooth-frwk-service.service
%{_unitdir_user}/bluetooth-frwk-service.service
%attr(0666,-,-) /opt/var/lib/bluetooth/auto-pair-blacklist
%{_sysconfdir}/dbus-1/system.d/bluetooth-frwk-service.conf
%if %{with bluetooth_frwk_libnotify}
%{_datadir}/icons/default/bt-icon.png
%endif

%files core
%manifest %{name}.manifest
%defattr(-, root, root)
%{_datadir}/dbus-1/system-services/org.projectx.bt_core.service
%{_bindir}/bt-core
%{_sysconfdir}/dbus-1/system.d/bluetooth-frwk-core.conf
