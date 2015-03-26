%define _dumpdir /opt/etc/dump.d/module.d
%define _varlibdir /opt/var/lib

Name:       bluetooth-frwk
Summary:    Bluetooth framework for BlueZ and Obexd. This package is Bluetooth framework based on BlueZ and Obexd stack.
Version:    0.2.146
Release:    1
Group:      Network & Connectivity/Bluetooth
License:    Apache License, Version 2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: bluetooth-frwk.manifest
URL:        https://review.tizen.org/git/?p=platform/core/connectivity/bluetooth-frwk.git;a=summary
Requires: sys-assert
Requires: dbus
Requires: syspopup
BuildRequires:  pkgconfig(aul)
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  pkgconfig(gio-unix-2.0)
BuildRequires:  pkgconfig(syspopup-caller)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(libxml-2.0)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(utilX)
BuildRequires:  pkgconfig(capi-network-connection)
BuildRequires:  pkgconfig(alarm-service)
BuildRequires:  pkgconfig(notification)
BuildRequires:  pkgconfig(security-server)
BuildRequires:  pkgconfig(capi-content-mime-type)
BuildRequires:  pkgconfig(appcore-efl)
BuildRequires:  pkgconfig(pkgmgr)
#BuildRequires:  pkgconfig(journal)

%if "%{?tizen_profile_name}" == "mobile"
BuildRequires:  pkgconfig(capi-network-tethering)
%endif

BuildRequires:  cmake

#Requires(post): vconf
#Requires(postun): eglibc
#Requires: psmisc
Requires(post): /usr/bin/vconftool
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
Requires(postun): eglibc
Requires: psmisc

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
Group:      Network & Connectivity/Bluetooth
Requires:   %{name} = %{version}-%{release}

%description service
This package is Bluetooth Service daemon to manage BT services.

%package core
Summary:    Bluetooth Core daemon
Group:      Network & Connectivity/Bluetooth
Requires:   %{name} = %{version}-%{release}

%description core
This package is Bluetooth core daemon to manage activation / deactivation.

%package test
Summary:    Bluetooth test application
Group:      Network & Connectivity/Bluetooth
Requires:   %{name} = %{version}-%{release}

%description test
This package is Bluetooth test application.

%prep
%setup -q
cp %{SOURCE1001} .


%build
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"

%if "%{?tizen_profile_name}" == "mobile"
export CFLAGS="$CFLAGS -DTIZEN_NETWORK_TETHERING_ENABLE"
%endif

%if "%{?tizen_profile_name}" == "wearable"
export CFLAGS="$CFLAGS -DTIZEN_WEARABLE"
%define _servicefile packaging/bluetooth-frwk-wearable.service
%else
%define _servicefile packaging/bluetooth-frwk-mobile.service
%endif
%define _servicedir multi-user.target.wants

%if "%{?tizen_profile_name}" == "mobile"
%else
export CFLAGS="$CFLAGS -DTIZEN_TELEPHONY_ENABLED"
%endif

export LDFLAGS+=" -Wl,--rpath=/usr/lib -Wl,--as-needed -Wl,--unresolved-symbols=ignore-in-shared-libs -pie"

export CFLAGS+=" -fpie -DRFCOMM_DIRECT "
cmake . -DCMAKE_INSTALL_PREFIX=/usr

make

%cmake \
%if "%{?tizen_profile_name}" == "wearable"
	-DTIZEN_WEARABLE=YES \
%else
	-DTIZEN_WEARABLE=NO \
%endif

%install
rm -rf %{buildroot}
%make_install

install -D -m 0644 LICENSE %{buildroot}%{_datadir}/license/bluetooth-frwk
install -D -m 0644 LICENSE %{buildroot}%{_datadir}/license/bluetooth-frwk-service
install -D -m 0644 LICENSE %{buildroot}%{_datadir}/license/bluetooth-frwk-devel

mkdir -p %{buildroot}%{_libdir}/systemd/system/%{_servicedir}
install -m 0644 %{_servicefile} %{buildroot}%{_libdir}/systemd/system/bluetooth-frwk.service
ln -s ../bluetooth-frwk.service %{buildroot}%{_libdir}/systemd/system/%{_servicedir}/bluetooth-frwk.service

mkdir -p %{buildroot}%{_dumpdir}
install -m 0755 bluetooth_log_dump.sh %{buildroot}%{_dumpdir}

%post
%if "%{?tizen_profile_name}" == "wearable"
vconftool set -tf int db/bluetooth/status "1" -g 5000 -s tizen::vconf::public::r::platform::rw
%else
vconftool set -tf int db/bluetooth/status "0" -g 5000 -s tizen::vconf::public::r::platform::rw
%endif
vconftool set -tf int db/bluetooth/lestatus "0" -g 5000 -s tizen::vconf::public::r::platform::rw
vconftool set -tf int file/private/bt-core/flight_mode_deactivated "0" -g 5000 -i -s tizen::vconf::platform::rw
vconftool set -tf int file/private/bt-core/powersaving_mode_deactivated "0" -g 5000 -i -s tizen::vconf::platform::rw
vconftool set -tf int file/private/bt-service/bt_off_due_to_timeout "0" -g 5000 -i -s tizen::vconf::platform::rw
vconftool set -tf string memory/bluetooth/sco_headset_name "" -g 5000 -i -s tizen::vconf::platform::rw
vconftool set -tf int memory/bluetooth/device "0" -g 5000 -i -s tizen::vconf::platform::rw
vconftool set -tf bool memory/bluetooth/dutmode "0" -g 5000 -i -s tizen::vconf::platform::rw

%post service
mkdir -p %{_sysconfdir}/systemd/default-extra-dependencies/ignore-units.d/
ln -sf %{_libdir}/systemd/system/bluetooth-frwk.service %{_sysconfdir}/systemd/default-extra-dependencies/ignore-units.d/

%postun -p /sbin/ldconfig

%files
%manifest %{name}.manifest
%defattr(-, root, root)
%{_libdir}/libbluetooth-api.so.*
%{_datadir}/license/bluetooth-frwk
%{_libdir}/systemd/system/%{_servicedir}/bluetooth-frwk.service
%{_libdir}/systemd/system/bluetooth-frwk.service

%files devel
%defattr(-, root, root)
%{_includedir}/bt-service/bluetooth-api.h
%{_includedir}/bt-service/bluetooth-hid-api.h
%{_includedir}/bt-service/bluetooth-audio-api.h
%{_includedir}/bt-service/bluetooth-telephony-api.h
%{_includedir}/bt-service/bluetooth-media-control.h
%{_includedir}/bt-service/bluetooth-scmst-api.h
%{_libdir}/pkgconfig/bluetooth-api.pc
%{_libdir}/libbluetooth-api.so
%{_datadir}/license/bluetooth-frwk-devel

%files service
%manifest %{name}.manifest
%defattr(-, root, root)
%{_sysconfdir}/rc.d/init.d/bluetooth-frwk-service
%{_datadir}/dbus-1/system-services/org.projectx.bt.service
%{_bindir}/bt-service
%{_bindir}/bluetooth-frwk-test
%{_bindir}/bluetooth-gatt-test
%{_bindir}/bluetooth-advertising-test
%{_varlibdir}/bluetooth
%{_prefix}/etc/bluetooth
%attr(0666,-,-) %{_varlibdir}/bluetooth/auto-pair-blacklist
%attr(0666,-,-) %{_prefix}/etc/bluetooth/stack_info
%{_dumpdir}/bluetooth_log_dump.sh
%{_datadir}/license/bluetooth-frwk-service

%files core
%manifest %{name}.manifest
%defattr(-, root, root)
%{_datadir}/dbus-1/system-services/org.projectx.bt_core.service
%{_bindir}/bt-core

%files test
%manifest %{name}.manifest
%defattr(-, root, root)
%{_bindir}/bluetooth-frwk-test
%{_bindir}/bluetooth-gatt-test
%{_bindir}/bluetooth-advertising-test
