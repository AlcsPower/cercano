// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only
//
// Interfaz de escritorio según el diseño objetivo (F3-23, docs/diseno/README.md).

import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/desktop/pages/connection_page.dart';
import 'package:flutter_hbb/desktop/pages/desktop_tab_page.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:flutter_hbb/models/server_model.dart';
import 'package:provider/provider.dart';

/// Paleta oficial de branding/README.md.
class CercanoColors {
  static const azul = Color(0xFF3B5BFF);
  static const verde = Color(0xFF2DD4A7);
  static const noche = Color(0xFF0B1426);
  static const niebla = Color(0xFFF2F5FB);
  static const borde = Color(0xFFDCE2EE);
  static const gris = Color(0xFF4A5878);
  static const rojo = Color(0xFFB42318);
}

const _kRadius = 14.0;
const _kMono = 'Consolas';

/// Rol del perfil firmado; vacío si no hay perfil (compilación sin generador).
String cercanoRole() => bind.mainGetBuildinOption(key: 'cercano-role');

bool isCercanoSupportRole() => cercanoRole() == 'soporte';

/// Texto del pie. Sin la palabra RustDesk (AGENTS.md §6).
String cercanoFooterText(String role, String version) {
  final parts = <String>[if (version.isNotEmpty) 'v$version'];
  if (role.isNotEmpty) parts.add('${translate('Role')}: $role');
  return parts.join(' · ');
}

class CercanoFooter extends StatelessWidget {
  const CercanoFooter({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    const style = TextStyle(fontSize: 12.5, color: CercanoColors.gris);
    return Container(
      height: 46,
      padding: const EdgeInsets.symmetric(horizontal: 30),
      decoration: const BoxDecoration(
        color: Color(0xFFFAFBFE),
        border: Border(top: BorderSide(color: CercanoColors.borde)),
      ),
      child: Row(children: [
        loadIcon(16),
        const SizedBox(width: 8),
        const Text.rich(
          TextSpan(style: style, children: [
            TextSpan(text: 'Powered by '),
            TextSpan(
                text: 'Cercano',
                style: TextStyle(
                    fontWeight: FontWeight.bold, color: CercanoColors.noche)),
            TextSpan(text: ' · AGPL-3.0'),
          ]),
        ),
        const Spacer(),
        Text(cercanoFooterText(cercanoRole(), version), style: style),
      ]),
    );
  }
}

Widget _card({required Widget child, EdgeInsets? margin}) => Container(
      margin: margin,
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 20),
      decoration: BoxDecoration(
        color: CercanoColors.niebla,
        border: Border.all(color: CercanoColors.borde),
        borderRadius: BorderRadius.circular(_kRadius),
      ),
      child: child,
    );

Widget _label(String text) => Text(
      translate(text).toUpperCase(),
      style: const TextStyle(
          fontSize: 12,
          fontWeight: FontWeight.w700,
          letterSpacing: 1,
          color: CercanoColors.gris),
    );

const _muted = TextStyle(fontSize: 13, color: CercanoColors.gris);

/// Pantalla principal del rol `soporte`: solo recibe asistencia.
class CercanoSupportHome extends StatelessWidget {
  const CercanoSupportHome({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return ChangeNotifierProvider.value(
      value: gFFI.serverModel,
      child: Consumer<ServerModel>(
        builder: (context, model, _) => Container(
          color: Colors.white,
          child: Column(children: [
            Expanded(
              child: SingleChildScrollView(
                padding: const EdgeInsets.fromLTRB(30, 26, 30, 20),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    _header(),
                    const SizedBox(height: 20),
                    _idCard(model),
                    const SizedBox(height: 16),
                    IntrinsicHeight(
                      child: Row(
                          crossAxisAlignment: CrossAxisAlignment.stretch,
                          children: [
                            Expanded(child: _passwordCard(model)),
                            const SizedBox(width: 16),
                            Expanded(child: _deviceCard()),
                          ]),
                    ),
                    const SizedBox(height: 20),
                    _actions(),
                    const SizedBox(height: 20),
                    Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                      const Icon(Icons.lock_outline,
                          size: 18, color: CercanoColors.gris),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Text(
                            translate('cercano-receive-only-tip'),
                            style: _muted.copyWith(height: 1.45)),
                      ),
                    ]),
                  ],
                ),
              ),
            ),
            const CercanoFooter(),
          ]),
        ),
      ),
    );
  }

  Widget _header() {
    final name = bind.mainGetAppNameSync();
    return Row(children: [
      Container(
        width: 56,
        height: 56,
        alignment: Alignment.center,
        decoration: BoxDecoration(
          color: CercanoColors.niebla,
          borderRadius: BorderRadius.circular(_kRadius),
        ),
        child: loadIcon(36),
      ),
      const SizedBox(width: 16),
      Expanded(
        child: Text(name,
            style: const TextStyle(
                fontSize: 22,
                fontWeight: FontWeight.w700,
                color: CercanoColors.noche)),
      ),
      // shortcut: estado heredado del servidor; la cápsula «Conectado al servidor» con
      // organización y contacto llega con la marca del agente (F3.5-10).
      const Flexible(child: OnlineStatusWidget()),
    ]);
  }

  Widget _idCard(ServerModel model) => _card(
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          _label('Your support ID'),
          const SizedBox(height: 6),
          GestureDetector(
            onDoubleTap: () {
              Clipboard.setData(ClipboardData(text: model.serverId.text));
              showToast(translate('Copied'));
            },
            child: SelectableText(
              model.serverId.text,
              style: const TextStyle(
                  fontFamily: _kMono,
                  fontSize: 40,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 4,
                  color: CercanoColors.noche),
            ),
          ),
          const SizedBox(height: 4),
          Text(translate('cercano-id-tip'), style: _muted),
        ]),
      );

  Widget _passwordCard(ServerModel model) => _card(
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          _label('One-time code'),
          const SizedBox(height: 6),
          Row(children: [
            Expanded(
              child: SelectableText(
                model.serverPasswd.text,
                style: const TextStyle(
                    fontFamily: _kMono,
                    fontSize: 22,
                    fontWeight: FontWeight.w600,
                    color: CercanoColors.noche),
              ),
            ),
            IconButton(
              tooltip: translate('Refresh Password'),
              icon: const Icon(Icons.refresh, color: CercanoColors.gris),
              onPressed: () => bind.mainUpdateTemporaryPassword(),
            ),
          ]),
          const SizedBox(height: 4),
          Text(translate('Changes every session'), style: _muted),
        ]),
      );

  Widget _deviceCard() => _card(
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          _label('Device'),
          const SizedBox(height: 6),
          Text(Platform.localHostname,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(
                  fontSize: 18,
                  fontWeight: FontWeight.w600,
                  color: CercanoColors.noche)),
          const SizedBox(height: 4),
          Text(Platform.operatingSystemVersion,
              maxLines: 1, overflow: TextOverflow.ellipsis, style: _muted),
        ]),
      );

  Widget _actions() => Row(children: [
        Expanded(
          child: cercanoButton(
            text: 'Support Chat',
            icon: Icons.chat_bubble_outline,
            primary: true,
            onPressed: DesktopTabPage.onAddChat,
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: cercanoButton(
            text: 'Settings',
            icon: Icons.settings_outlined,
            onPressed: DesktopTabPage.onAddSetting,
          ),
        ),
      ]);
}

Widget cercanoButton({
  required String text,
  required VoidCallback onPressed,
  IconData? icon,
  bool primary = false,
  Color? textColor,
  double height = 52,
}) {
  final fg = textColor ?? (primary ? Colors.white : CercanoColors.noche);
  final style = ElevatedButton.styleFrom(
    elevation: 0,
    minimumSize: Size.fromHeight(height),
    backgroundColor: primary ? CercanoColors.azul : Colors.white,
    foregroundColor: fg,
    side: BorderSide(color: primary ? CercanoColors.azul : CercanoColors.borde),
    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
    textStyle: const TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
  );
  final label = Text(translate(text));
  return icon == null
      ? ElevatedButton(style: style, onPressed: onPressed, child: label)
      : ElevatedButton.icon(
          style: style,
          onPressed: onPressed,
          icon: Icon(icon, size: 18),
          label: label);
}

/// Diálogo de consentimiento de una sesión entrante (ventana de gestión de conexiones).
class CercanoConsentCard extends StatelessWidget {
  final Client client;
  final VoidCallback onAccept;
  final VoidCallback onReject;

  const CercanoConsentCard(
      {Key? key,
      required this.client,
      required this.onAccept,
      required this.onReject})
      : super(key: key);

  @override
  Widget build(BuildContext context) {
    final initials = client.name.trim().isEmpty
        ? '?'
        : client.name
            .trim()
            .split(RegExp(r'\s+'))
            .take(2)
            .map((w) => w[0].toUpperCase())
            .join();
    return Container(
      color: Colors.white,
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 12),
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        Row(children: [
          CircleAvatar(
            radius: 24,
            backgroundColor: const Color(0xFFE3E9FF),
            child: Text(initials,
                style: const TextStyle(
                    color: CercanoColors.azul,
                    fontWeight: FontWeight.w700,
                    fontSize: 18)),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('${client.name} ${translate('wants to connect')}',
                      style: const TextStyle(
                          fontSize: 17,
                          fontWeight: FontWeight.w700,
                          color: CercanoColors.noche)),
                  const SizedBox(height: 2),
                  // shortcut: el ticket y la organización del técnico no viajan en la
                  // solicitud entrante; se muestran cuando el agente los entregue (F3.5).
                  Text('${translate('Technician')} · ID ${client.peerId}',
                      style: _muted),
                ]),
          ),
        ]),
        const SizedBox(height: 16),
        Container(
          decoration: BoxDecoration(
            border: Border.all(color: CercanoColors.borde),
            borderRadius: BorderRadius.circular(12),
          ),
          child: Column(children: [
            _perm('View the screen', true, first: true),
            _perm('Use keyboard and mouse', client.keyboard),
            _perm('Transfer files', client.file),
            _perm('Record the session', client.recording),
          ]),
        ),
        const SizedBox(height: 12),
        Text(translate('cercano-end-session-tip'), style: _muted),
        const Spacer(),
        Row(children: [
          Expanded(
            child: cercanoButton(
                text: 'Reject',
                onPressed: onReject,
                textColor: CercanoColors.rojo,
                height: 48),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: cercanoButton(
                text: 'Accept session',
                onPressed: onAccept,
                primary: true,
                height: 48),
          ),
        ]),
      ]),
    );
  }

  Widget _perm(String text, bool allowed, {bool first = false}) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
        decoration: BoxDecoration(
          border: first
              ? null
              : const Border(top: BorderSide(color: CercanoColors.borde)),
        ),
        child: Row(children: [
          Expanded(
              child: Text(translate(text),
                  style: const TextStyle(
                      fontSize: 14, color: CercanoColors.noche))),
          Text(
            translate(allowed ? 'Allowed' : 'Not allowed'),
            style: allowed
                ? const TextStyle(
                    color: Color(0xFF0B7A5E), fontWeight: FontWeight.w600)
                : const TextStyle(color: Color(0xFF9AA3B5)),
          ),
        ]),
      );
}
