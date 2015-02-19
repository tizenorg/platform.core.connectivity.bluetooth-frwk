%define _dumpdir /opt/etc/dump.d/module.d
%define _varlibdir /opt/var/lib
#%bcond_with bluetooth_frwk_libnotify
#%bcond_with bluetooth_frwk_libnotification
#%bcond_with x

Name:       bluetooth-frwk
Summary:    Bluetooth framework for BlueZ and Obexd. This package is Bluetooth framework based on BlueZ and Obexd stack.
Version:    0.2.146
Release:    0
Group:      Network & Connectivity/Bluetooth
License:    Apache License, Version 2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: bluetooth-frwk.manifest
Source1002: bt-icon.png
URL:        https://review.tizen.org/git/?p=platform/core/connectivity/bluetooth-frwk.git;a=summary
Requires: dbus
Requires: syspopup
Requires: bluetooth-tools
BuildRequires:  pkgconfig(aul)
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  pkgconfig(gio-unix-2.0)
%if %{with bluetooth_frwk_libnotify}
BuildRequires:  pkgconfig(libnotify)
BuildRequires:  pkgconfig(gdk-pixbuf-2.0)
BuildRequires:  pkgconfig(gtk+-3.0)
%elif %{without bluetooth_frwk_libnotification}
BuildRequires:  pkgconfig(syspopup-caller)
Requires:       syspopup
%else
BuildRequires:  pkgconfig(syspopup-caller)
%endif
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(libxml-2.0)
BuildRequires:  pkgconfig(dbus-1)
#%if %{with x}
BuildRequires:  pkgconfig(utilX)
#%endif
BuildRequires:  pkgconfig(capi-network-connection)

BuildRequires:  pkgconfig(libprivilege-control)
BuildRequires:  pkgconfig(status)
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
BuildRequires:  pkgconfig(libtzplatform-config)

Requires(post): /usr/bin/vconftool
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
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
Requires:   connman

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

%ifarch x86_64
export CFLAGS+=" -Wall -g -fvisibility=hidden -fPIC -DRFCOMM_DIRECT "
export LDFLAGS+=" -Wl,--rpath=%{_libdir} -Wl,--as-needed -Wl,--unresolved-symbols=ignore-in-shared-libs"
%else
export CFLAGS+=" -fpie -DRFCOMM_DIRECT "
export LDFLAGS+=" -Wl,--rpath=/usr/lib -Wl,--as-needed -Wl,--unresolved-symbols=ignore-in-shared-libs -pie"
%endif

%cmake . \
-DTZ_SYS_USER_GROUP=%TZ_SYS_USER_GROUP \
-DTZ_SYS_DEFAULT_USER=%TZ_SYS_DEFAULT_USER \
%if %{with bluetooth_frwk_libnotify}
 -DLIBNOTIFY_SUPPORT=On \
%else
 -DLIBNOTIFY_SUPPORT=Off \
%endif
%if %{with bluetooth_frwk_libnotification}
 -DLIBNOTIFICATION_SUPPORT=On
%else
 -DLIBNOTIFICATION_SUPPORT=Off
%endif

%cmake \
%if "%{?tizen_profile_name}" == "wearable"
	-DTIZEN_WEARABLE=YES \
%else
	-DTIZEN_WEARABLE=NO \
%endif

%__make

%install
rm -rf %{buildroot}
%make_install

install -D -m 0644 LICENSE %{buildroot}%{_datadir}/license/bluetooth-frwk
install -D -m 0644 LICENSE %{buildroot}%{_datadir}/license/bluetooth-frwk-service
install -D -m 0644 LICENSE %{buildroot}%{_datadir}/license/bluetooth-frwk-devel

mkdir -p %{buildroot}%{_unitdir_user}
install -m 0644 bt-service/bluetooth-frwk-service.service %{buildroot}%{_unitdir_user}

%if %{with bluetooth_frwk_libnotify} || %{with bluetooth_frwk_libnotification}
mkdir -p %{buildroot}%{_datadir}/icons/default
install -m 0644 %{SOURCE1002} %{buildroot}%{_datadir}/icons/default/bt-icon.png
%endif

# On IVI bt-service needs to be run as 'app' even if there is a 'guest' user.
%if "%{profile}"=="ivi"
sed -i 's/%TZ_SYS_DEFAULT_USER/app/' %{buildroot}%{_datadir}/dbus-1/system-services/org.projectx.bt.service
%endif

mkdir -p %{buildroot}%{_dumpdir}
install -m 0755 bluetooth_log_dump.sh %{buildroot}%{_dumpdir}

%post
/sbin/ldconfig
%if "%{?tizen_profile_name}" == "wearable"
vconftool set -f -t int db/bluetooth/status "1" -g 6520
%else
vconftool set -f -t int db/bluetooth/status "0" -g 6520
%endif

vconftool set -f -t int db/bluetooth/lestatus "0" -g 6520 -i
vconftool set -f -t int file/private/bt-service/flight_mode_deactivated "0" -g 6520 -i
vconftool set -f -t int file/private/bt-core/flight_mode_deactivated "0" -g 6520 -i
vconftool set -f -t int file/private/bt-core/powersaving_mode_deactivated "0" -g 6520 -i
vconftool set -f -t int file/private/bt-service/bt_off_due_to_timeout "0" -g 6520 -i
vconftool set -f -t string memory/bluetooth/sco_headset_name "" -g 6520 -i
vconftool set -f -t int memory/bluetooth/device "0" -g 6520 -i
vconftool set -f -t int memory/bluetooth/btsco "0" -g 6520 -i
vconftool set -f -t bool memory/bluetooth/dutmode "0" -g 6520 -i
# set 'User' smack label to vconf keys in order to allow bt-service to access them.
chsmack -a 'User' %TZ_SYS_CONFIG/db/bluetooth/status
chsmack -a 'User' %TZ_SYS_CONFIG/file/private/bt-service/flight_mode_deactivated
chsmack -a 'User' %TZ_SYS_CONFIG/memory_init/memory/bluetooth/sco_headset_name
chsmack -a 'User' %TZ_SYS_CONFIG/memory_init/memory/bluetooth/device
chsmack -a 'User' %TZ_SYS_CONFIG/memory_init/memory/bluetooth/btsco

%post service
mkdir -p %{_sysconfdir}/systemd/default-extra-dependencies/ignore-units.d/
ln -sf %{_libdir}/systemd/system/bluetooth-frwk.service %{_sysconfdir}/systemd/default-extra-dependencies/ignore-units.d/

%postun -p /sbin/ldconfig

%files
%manifest %{name}.manifest
%defattr(-, root, root)
%{_libdir}/libbluetooth-api.so.*
%{_datadir}/license/bluetooth-frwk

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
%{_datadir}/dbus-1/system-services/org.projectx.bt.service
%{_bindir}/bt-service
%{_unitdir_user}/bluetooth-frwk-service.service
%{_bindir}/bluetooth-frwk-test
%{_bindir}/bluetooth-gatt-test
%{_bindir}/bluetooth-advertising-test
%{_varlibdir}/bluetooth
%{_prefix}/etc/bluetooth
#%attr(0666,-,-) %{_varlibdir}/bluetooth/auto-pair-blacklist
#%{_sysconfdir}/dbus-1/system.d/bluetooth-frwk-service.conf
#%attr(0666,-,-) %{_prefix}/etc/bluetooth/stack_info
%{_dumpdir}/bluetooth_log_dump.sh
%{_datadir}/license/bluetooth-frwk-service
%if %{with bluetooth_frwk_libnotify} || %{with bluetooth_frwk_libnotification}
%{_datadir}/icons/default/bt-icon.png
%endif

%files core
%manifest %{name}.manifest
%defattr(-, root, root)
%{_datadir}/dbus-1/system-services/org.projectx.bt_core.service
%{_bindir}/bt-core
#%{_sysconfdir}/dbus-1/system.d/bluetooth-frwk-core.conf

%files test
%manifest %{name}.manifest
%defattr(-, root, root)
%{_bindir}/bluetooth-frwk-test
%{_bindir}/bluetooth-gatt-test
%{_bindir}/bluetooth-advertising-test
