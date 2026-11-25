// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart';
import 'package:provider/provider.dart';
import 'cercano_chat_model.dart';

Color _parseColor(String hexString, Color defaultColor) {
  try {
    final buffer = StringBuffer();
    if (hexString.length == 6 || hexString.length == 7) buffer.write('ff');
    buffer.write(hexString.replaceFirst('#', ''));
    return Color(int.parse(buffer.toString(), radix: 16));
  } catch (_) {
    return defaultColor;
  }
}

class CercanoChatPage extends StatefulWidget {
  const CercanoChatPage({Key? key}) : super(key: key);

  @override
  State<CercanoChatPage> createState() => _CercanoChatPageState();
}

class _CercanoChatPageState extends State<CercanoChatPage> {
  final _firstNameController = TextEditingController();
  final _lastNameController = TextEditingController();
  final _initialMsgController = TextEditingController();
  final _composerController = TextEditingController();
  final _scrollController = ScrollController();
  bool _showNotice = true;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final model = Provider.of<CercanoChatModel>(context, listen: false);
      model.init().then((_) {
        _firstNameController.text = model.contactFirstName;
        _lastNameController.text = model.contactLastName;
      });
    });
  }

  @override
  void dispose() {
    _firstNameController.dispose();
    _lastNameController.dispose();
    _initialMsgController.dispose();
    _composerController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  void _scrollToBottom() {
    if (_scrollController.hasClients) {
      _scrollController.animateTo(
        _scrollController.position.maxScrollExtent + 80,
        duration: const Duration(milliseconds: 200),
        curve: Curves.easeOut,
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return ChangeNotifierProvider<CercanoChatModel>(
      create: (_) => CercanoChatModel(),
      child: Consumer<CercanoChatModel>(
        builder: (context, model, _) {
          final accentColor = _parseColor(model.branding.accentColor, const Color(0xFF3B5BFF));
          final isDark = Theme.of(context).brightness == Brightness.dark;

          return Scaffold(
            body: Column(
              children: [
                _buildHeader(context, model, accentColor),
                if (_showNotice) _buildNotice(context, model),
                Expanded(
                  child: model.isLoading
                      ? const Center(child: CircularProgressIndicator())
                      : model.conversation == null
                          ? _buildOnboarding(context, model, accentColor)
                          : _buildThread(context, model, accentColor, isDark),
                ),
                if (model.conversation != null && !model.conversation!.isClosed)
                  _buildComposer(context, model, accentColor),
                _buildPrivacyFooter(context, model),
              ],
            ),
          );
        },
      ),
    );
  }

  Widget _buildHeader(BuildContext context, CercanoChatModel model, Color accentColor) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      decoration: BoxDecoration(
        color: Theme.of(context).cardColor,
        border: Border(
          bottom: BorderSide(
            color: Theme.of(context).dividerColor.withOpacity(0.1),
          ),
        ),
      ),
      child: Row(
        children: [
          Container(
            width: 36,
            height: 36,
            decoration: BoxDecoration(
              color: accentColor.withOpacity(0.15),
              borderRadius: BorderRadius.circular(10),
            ),
            child: Icon(Icons.support_agent, color: accentColor, size: 22),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Soporte ${model.branding.supportName}',
                  style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 15),
                  overflow: TextOverflow.ellipsis,
                ),
                Text(
                  model.branding.organizationName,
                  style: TextStyle(
                    fontSize: 12,
                    color: Theme.of(context).textTheme.bodySmall?.color,
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
          Row(
            children: [
              Container(
                width: 8,
                height: 8,
                decoration: BoxDecoration(
                  color: model.isOnline ? Colors.green : Colors.amber,
                  shape: BoxShape.circle,
                ),
              ),
              const SizedBox(width: 6),
              Text(
                model.isOnline ? 'En línea' : 'Reconectando',
                style: TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                  color: model.isOnline ? Colors.green.shade700 : Colors.amber.shade800,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildNotice(BuildContext context, CercanoChatModel model) {
    return Container(
      margin: const EdgeInsets.all(12),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: Theme.of(context).cardColor,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Theme.of(context).dividerColor.withOpacity(0.08)),
      ),
      child: Row(
        children: [
          const Icon(Icons.info_outline, size: 18, color: Colors.blue),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              model.branding.infoText,
              style: const TextStyle(fontSize: 12),
            ),
          ),
          IconButton(
            icon: const Icon(Icons.close, size: 16),
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(),
            onPressed: () => setState(() => _showNotice = false),
          ),
        ],
      ),
    );
  }

  Widget _buildOnboarding(BuildContext context, CercanoChatModel model, Color accentColor) {
    return SingleChildScrollView(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const SizedBox(height: 12),
          Text(
            model.branding.welcomeText,
            style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w500),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 24),
          const Text(
            'Datos de contacto obligatorios',
            style: TextStyle(fontSize: 13, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _firstNameController,
            decoration: const InputDecoration(
              labelText: 'Nombre *',
              border: OutlineInputBorder(),
              contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
            ),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _lastNameController,
            decoration: const InputDecoration(
              labelText: 'Apellido *',
              border: OutlineInputBorder(),
              contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
            ),
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _initialMsgController,
            maxLines: 3,
            decoration: const InputDecoration(
              labelText: '¿En qué podemos ayudarle?',
              hintText: 'Describa brevemente el problema...',
              border: OutlineInputBorder(),
            ),
          ),
          if (model.errorMessage != null) ...[
            const SizedBox(height: 12),
            Text(
              model.errorMessage!,
              style: const TextStyle(color: Colors.red, fontSize: 12),
              textAlign: TextAlign.center,
            ),
          ],
          const SizedBox(height: 20),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: accentColor,
              foregroundColor: Colors.white,
              padding: const EdgeInsets.symmetric(vertical: 14),
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
            ),
            onPressed: () async {
              final ok = await model.saveContactInfo(
                _firstNameController.text,
                _lastNameController.text,
              );
              if (ok) {
                await model.startConversation(_initialMsgController.text);
              }
            },
            child: const Text('Iniciar conversación', style: TextStyle(fontWeight: FontWeight.bold)),
          ),
        ],
      ),
    );
  }

  Widget _buildThread(
    BuildContext context,
    CercanoChatModel model,
    Color accentColor,
    bool isDark,
  ) {
    final messages = model.conversation?.messages ?? [];

    return ListView.builder(
      controller: _scrollController,
      padding: const EdgeInsets.all(16),
      itemCount: messages.length,
      itemBuilder: (context, index) {
        final msg = messages[index];
        if (msg.isSystem) {
          return Center(
            child: Container(
              margin: const EdgeInsets.symmetric(vertical: 8),
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
              decoration: BoxDecoration(
                color: isDark ? Colors.grey.shade800 : Colors.grey.shade200,
                borderRadius: BorderRadius.circular(12),
              ),
              child: Text(
                msg.body,
                style: TextStyle(
                  fontSize: 11,
                  color: isDark ? Colors.grey.shade400 : Colors.grey.shade700,
                ),
              ),
            ),
          );
        }

        final isMine = msg.isMine;
        final isRead = model.isMessageRead(msg);

        return Align(
          alignment: isMine ? Alignment.centerRight : Alignment.centerLeft,
          child: Container(
            margin: const EdgeInsets.symmetric(vertical: 4),
            constraints: BoxConstraints(maxWidth: MediaQuery.of(context).size.width * 0.75),
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
            decoration: BoxDecoration(
              color: isMine
                  ? accentColor
                  : isDark
                      ? Colors.grey.shade800
                      : Colors.grey.shade200,
              borderRadius: BorderRadius.only(
                topLeft: const Radius.circular(14),
                topRight: const Radius.circular(14),
                bottomLeft: Radius.circular(isMine ? 14 : 2),
                bottomRight: Radius.circular(isMine ? 2 : 14),
              ),
            ),
            child: Column(
              crossAxisAlignment:
                  isMine ? CrossAxisAlignment.end : CrossAxisAlignment.start,
              children: [
                if (!isMine && msg.senderName != null)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 2),
                    child: Text(
                      msg.senderName!,
                      style: TextStyle(
                        fontSize: 11,
                        fontWeight: FontWeight.bold,
                        color: isDark ? Colors.grey.shade300 : Colors.grey.shade800,
                      ),
                    ),
                  ),
                if (msg.body.isNotEmpty)
                  Text(
                    msg.body,
                    style: TextStyle(
                      color: isMine
                          ? Colors.white
                          : isDark
                              ? Colors.white
                              : Colors.black87,
                      fontSize: 14,
                    ),
                  ),
                if (msg.attachment != null) ...[
                  const SizedBox(height: 6),
                  Container(
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      color: Colors.black12,
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const Icon(Icons.attach_file, size: 16, color: Colors.white),
                        const SizedBox(width: 6),
                        Flexible(
                          child: Text(
                            msg.attachment!.name,
                            style: const TextStyle(fontSize: 12, color: Colors.white),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
                const SizedBox(height: 4),
                Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(
                      _formatTime(msg.createdAt),
                      style: TextStyle(
                        fontSize: 10,
                        color: isMine ? Colors.white70 : Colors.black45,
                      ),
                    ),
                    if (isMine) ...[
                      const SizedBox(width: 4),
                      Icon(
                        isRead ? Icons.done_all : Icons.done,
                        size: 13,
                        color: isRead ? Colors.cyanAccent : Colors.white70,
                      ),
                    ],
                  ],
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _buildComposer(BuildContext context, CercanoChatModel model, Color accentColor) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: Theme.of(context).cardColor,
        border: Border(
          top: BorderSide(
            color: Theme.of(context).dividerColor.withOpacity(0.1),
          ),
        ),
      ),
      child: Row(
        children: [
          Expanded(
            child: RawKeyboardListener(
              focusNode: FocusNode(),
              onKey: (event) {
                if (event is RawKeyDownEvent &&
                    event.logicalKey == LogicalKeyboardKey.enter &&
                    !event.isShiftPressed) {
                  _send(model);
                }
              },
              child: TextField(
                controller: _composerController,
                maxLines: null,
                decoration: const InputDecoration(
                  hintText: 'Escriba su mensaje...',
                  border: InputBorder.none,
                  contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                ),
              ),
            ),
          ),
          IconButton(
            icon: Icon(Icons.send, color: accentColor),
            onPressed: () => _send(model),
          ),
        ],
      ),
    );
  }

  void _send(CercanoChatModel model) async {
    final text = _composerController.text.trim();
    if (text.isEmpty) return;
    _composerController.clear();
    await model.sendMessage(text);
    _scrollToBottom();
  }

  Widget _buildPrivacyFooter(BuildContext context, CercanoChatModel model) {
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 6, horizontal: 16),
      color: Theme.of(context).cardColor.withOpacity(0.5),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(Icons.shield_outlined, size: 12, color: Colors.grey),
          const SizedBox(width: 6),
          Flexible(
            child: Text(
              model.branding.privacyText,
              style: const TextStyle(fontSize: 10, color: Colors.grey),
              textAlign: TextAlign.center,
            ),
          ),
        ],
      ),
    );
  }

  String _formatTime(String isoString) {
    try {
      final date = DateTime.parse(isoString).toLocal();
      final hour = date.hour.toString().padLeft(2, '0');
      final minute = date.minute.toString().padLeft(2, '0');
      return '$hour:$minute';
    } catch (_) {
      return '';
    }
  }
}
