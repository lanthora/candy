#
# spec file for package candy
#
# Copyright (c) 2024 SUSE LLC
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via https://bugs.opensuse.org/
#

Name:           candy
Version:        9999
Release:        0
Summary:        A reliable, low-latency, and anti-censorship VPN
License:        MIT
Group:          Productivity/Networking/Security
URL:            https://github.com/lanthora/candy
Source:         candy.tar.gz
BuildRequires:  cmake
BuildRequires:  gcc13-c++
BuildRequires:  libopenssl-devel
BuildRequires:  poco-devel
BuildRequires:  pcre2-devel
BuildRequires:  fmt-devel
BuildRequires:  spdlog-devel
BuildRequires:  systemd-rpm-macros
Requires:  openssl

%description
A reliable, low-latency, and anti-censorship virtual private network

%prep
%setup -q -n candy

%build
%cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=g++-13
%make_build

%install
%cmake_install

install -D -m 644 candy.cfg %{buildroot}/etc/candy.cfg
install -D -m 644 candy.service %{buildroot}%{_unitdir}/candy.service
install -D -m 644 candy@.service %{buildroot}%{_unitdir}/candy@.service

%pre
%service_add_pre candy.service candy@.service

%post
%service_add_post candy.service candy@.service

%preun
%service_del_preun candy.service candy@.service

%postun
%service_del_postun candy.service candy@.service

%files
%doc README.md
%{_bindir}/candy
%config(noreplace) /etc/candy.cfg
%{_unitdir}/candy.service
%{_unitdir}/candy@.service

%changelog
