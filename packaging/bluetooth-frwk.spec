Name:       bluetooth-frwk
Summary:    Bluetooth framework for BlueZ This package is Bluetooth framework based on Blue
Version:    0.1.21
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
BuildRequires:  pkgconfig(bluez)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(appcore-efl)
BuildRequires:  pkgconfig(openobex)
BuildRequires:  cmake

Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description
Bluetooth framework for BlueZ This package is Bluetooth framework based on BlueZ stack.
 This package contains API set for BT GAP, BT SDP, and BT RFCOMM.


%package devel
Summary:    Bluetooth framework for BlueZ
Group:      TO_BE/FILLED
Requires:   %{name} = %{version}-%{release}

%description devel
This package is development files for Bluetooth framework based on BlueZ stack.
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

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
/usr/lib/*.so.*

%files devel
/usr/lib/*.so
/usr/include/*
/usr/lib/pkgconfig/*

%files agent
/usr/bin/bluetooth-agent
/usr/bin/bluetooth-pb-agent
/etc/*
/usr/share/process-info/bluetooth-agent.ini
/usr/share/dbus-1/services/org.bluez.frwk_agent.service
/usr/share/dbus-1/services/org.bluez.pb_agent.service
