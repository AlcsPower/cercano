// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:flutter_hbb/common.dart';
import 'cercano_chat_ffi_bridge.dart';

class ChatBranding {
  final String supportName;
  final String organizationName;
  final String? logoUrl;
  final String accentColor;
  final String welcomeText;
  final String infoText;
  final String privacyText;

  ChatBranding({
    required this.supportName,
    required this.organizationName,
    this.logoUrl,
    required this.accentColor,
    required this.welcomeText,
    required this.infoText,
    required this.privacyText,
  });

  factory ChatBranding.defaultBranding() {
    return ChatBranding(
      supportName: 'Cercano Soporte',
      organizationName: 'Soporte interno',
      logoUrl: null,
      accentColor: '#3B5BFF',
      welcomeText: 'Cuéntanos qué necesitas y un técnico te atenderá.',
      infoText: 'Está conversando con el equipo de soporte.',
      privacyText: 'Su conversación es privada y se guarda para seguimiento.',
    );
  }

  factory ChatBranding.fromJson(Map<String, dynamic> json) {
    return ChatBranding(
      supportName: json['support_name'] ?? 'Cercano Soporte',
      organizationName: json['organization_name'] ?? 'Soporte interno',
      logoUrl: json['logo_url'],
      accentColor: json['accent_color'] ?? '#3B5BFF',
      welcomeText: json['welcome_text'] ??
          'Cuéntanos qué necesitas y un técnico te atenderá.',
      infoText: json['info_text'] ??
          'Está conversando con el equipo de soporte.',
      privacyText: json['privacy_text'] ??
          'Su conversación es privada y se guarda para seguimiento.',
    );
  }
}

class ChatAttachment {
  final String id;
  final String name;
  final String mime;
  final int sizeBytes;
  final String sha256;

  ChatAttachment({
    required this.id,
    required this.name,
    required this.mime,
    required this.sizeBytes,
    required this.sha256,
  });

  factory ChatAttachment.fromJson(Map<String, dynamic> json) {
    return ChatAttachment(
      id: json['id'] ?? '',
      name: json['name'] ?? '',
      mime: json['mime'] ?? '',
      sizeBytes: json['size_bytes'] ?? 0,
      sha256: json['sha256'] ?? '',
    );
  }

  bool get isImage =>
      mime.startsWith('image/') ||
      name.endsWith('.png') ||
      name.endsWith('.jpg') ||
      name.endsWith('.jpeg') ||
      name.endsWith('.webp');
}

class ChatMessage {
  final String id;
  final String conversationId;
  final String senderType;
  final String senderId;
  final String? senderName;
  final String body;
  final ChatAttachment? attachment;
  final String createdAt;

  ChatMessage({
    required this.id,
    required this.conversationId,
    required this.senderType,
    required this.senderId,
    this.senderName,
    required this.body,
    this.attachment,
    required this.createdAt,
  });

  factory ChatMessage.fromJson(Map<String, dynamic> json) {
    return ChatMessage(
      id: json['id'] ?? '',
      conversationId: json['conversation_id'] ?? '',
      senderType: json['sender_type'] ?? 'technician',
      senderId: json['sender_id'] ?? '',
      senderName: json['sender_name'],
      body: json['body'] ?? '',
      attachment: json['attachment'] != null
          ? ChatAttachment.fromJson(json['attachment'])
          : null,
      createdAt: json['created_at'] ?? DateTime.now().toIso8601String(),
    );
  }

  bool get isMine => senderType == 'device' || senderType == 'client';
  bool get isSystem => senderType == 'system';
}

class ChatConversation {
  final String id;
  final String deviceId;
  final String status;
  final String contactFirstName;
  final String contactLastName;
  final String? assignedUserId;
  final String? assignedDisplayName;
  final String? otherLastReadAt;
  final String createdAt;
  final String updatedAt;
  final List<ChatMessage> messages;

  ChatConversation({
    required this.id,
    required this.deviceId,
    required this.status,
    required this.contactFirstName,
    required this.contactLastName,
    this.assignedUserId,
    this.assignedDisplayName,
    this.otherLastReadAt,
    required this.createdAt,
    required this.updatedAt,
    this.messages = const [],
  });

  factory ChatConversation.fromJson(Map<String, dynamic> json) {
    var msgs = <ChatMessage>[];
    if (json['messages'] != null && json['messages'] is List) {
      msgs = (json['messages'] as List)
          .map((m) => ChatMessage.fromJson(m as Map<String, dynamic>))
          .toList();
    }
    return ChatConversation(
      id: json['id'] ?? '',
      deviceId: json['device_id'] ?? '',
      status: json['status'] ?? 'waiting',
      contactFirstName: json['contact_first_name'] ?? '',
      contactLastName: json['contact_last_name'] ?? '',
      assignedUserId: json['assigned_user_id'],
      assignedDisplayName: json['assigned_display_name'],
      otherLastReadAt: json['other_last_read_at'],
      createdAt: json['created_at'] ?? DateTime.now().toIso8601String(),
      updatedAt: json['updated_at'] ?? DateTime.now().toIso8601String(),
      messages: msgs,
    );
  }

  bool get isClosed => status == 'closed';
  bool get isAssigned => status == 'assigned' || status == 'active';
}

/// F4.5-17: nombre visible del técnico o respaldo genérico; nunca su login.
String technicianLabel(String? displayName, String organizationName) {
  final name = displayName?.trim() ?? '';
  return name.isNotEmpty ? name : 'un técnico de $organizationName';
}

/// Aviso «Ahora te atiende …» cuando cambia el técnico asignado; null si no cambió.
String? reassignmentNotice(
    ChatConversation? previous, ChatConversation next, String organizationName) {
  final before = previous?.assignedUserId;
  final after = next.assignedUserId;
  if (before == null || after == null || before == after) return null;
  return 'Ahora te atiende ${technicianLabel(next.assignedDisplayName, organizationName)}';
}

class CercanoChatModel extends ChangeNotifier {
  ChatBranding branding = ChatBranding.defaultBranding();
  ChatConversation? conversation;
  String contactFirstName = '';
  String contactLastName = '';
  bool isLoading = false;
  bool isSending = false;
  bool isOnline = true;
  String? errorMessage;
  String? technicianNotice;

  String get assignedTechnicianLabel => technicianLabel(
      conversation?.assignedDisplayName, branding.organizationName);

  bool get hasSavedContact =>
      contactFirstName.trim().isNotEmpty && contactLastName.trim().isNotEmpty;

  Future<void> init() async {
    isLoading = true;
    notifyListeners();

    try {
      // 1. Cargar nombre de contacto guardado localmente
      contactFirstName =
          await bind.mainGetLocalOption(key: 'chat-contact-first-name');
      contactLastName =
          await bind.mainGetLocalOption(key: 'chat-contact-last-name');

      // 2. Obtener branding desde cercano-api
      final apiServer = await bind.mainGetApiServer();
      final brandingJson = await CercanoChatFfiBridge.getBranding(apiServer);
      if (brandingJson.isNotEmpty) {
        final parsed = jsonDecode(brandingJson);
        branding = ChatBranding.fromJson(parsed);
      }

      // 3. Iniciar listener de SSE en Rust si está disponible
      CercanoChatFfiBridge.startEventsListener(apiServer);
    } catch (e) {
      debugPrint('Error inicializando CercanoChat: $e');
    } finally {
      isLoading = false;
      notifyListeners();
    }
  }

  Future<bool> saveContactInfo(String firstName, String lastName) async {
    final cleanFirst = firstName.trim();
    final cleanLast = lastName.trim();
    if (cleanFirst.isEmpty || cleanLast.isEmpty) {
      errorMessage = 'Nombre y Apellido son obligatorios.';
      notifyListeners();
      return false;
    }

    contactFirstName = cleanFirst;
    contactLastName = cleanLast;
    await bind.mainSetLocalOption(
        key: 'chat-contact-first-name', value: cleanFirst);
    await bind.mainSetLocalOption(
        key: 'chat-contact-last-name', value: cleanLast);
    errorMessage = null;
    notifyListeners();
    return true;
  }

  Future<void> startConversation(String initialMessage) async {
    if (!hasSavedContact) return;
    if (initialMessage.trim().isEmpty) {
      errorMessage = 'Por favor escriba un mensaje inicial.';
      notifyListeners();
      return;
    }

    isLoading = true;
    errorMessage = null;
    notifyListeners();

    try {
      final apiServer = await bind.mainGetApiServer();
      final resJson = await CercanoChatFfiBridge.createConversation(
        apiServer: apiServer,
        firstName: contactFirstName,
        lastName: contactLastName,
        initialMessage: initialMessage.trim(),
      );

      final parsed = jsonDecode(resJson);
      if (parsed['error'] != null) {
        errorMessage = parsed['error'].toString();
      } else {
        conversation = ChatConversation.fromJson(parsed);
      }
    } catch (e) {
      errorMessage = 'No se pudo iniciar la conversación: $e';
    } finally {
      isLoading = false;
      notifyListeners();
    }
  }

  Future<void> sendMessage(String text) async {
    if (conversation == null || text.trim().isEmpty || isSending) return;
    isSending = true;
    errorMessage = null;
    notifyListeners();

    try {
      final apiServer = await bind.mainGetApiServer();
      final resJson = await CercanoChatFfiBridge.sendMessage(
        apiServer: apiServer,
        conversationId: conversation!.id,
        body: text.trim(),
      );

      final parsed = jsonDecode(resJson);
      if (parsed['error'] != null) {
        errorMessage = parsed['error'].toString();
      } else {
        final newMsg = ChatMessage.fromJson(parsed);
        final updatedMsgs = List<ChatMessage>.from(conversation!.messages)
          ..add(newMsg);
        conversation = ChatConversation(
          id: conversation!.id,
          deviceId: conversation!.deviceId,
          status: conversation!.status,
          contactFirstName: conversation!.contactFirstName,
          contactLastName: conversation!.contactLastName,
          assignedUserId: conversation!.assignedUserId,
          assignedDisplayName: conversation!.assignedDisplayName,
          otherLastReadAt: conversation!.otherLastReadAt,
          createdAt: conversation!.createdAt,
          updatedAt: DateTime.now().toIso8601String(),
          messages: updatedMsgs,
        );
      }
    } catch (e) {
      errorMessage = 'Error enviando mensaje: $e';
    } finally {
      isSending = false;
      notifyListeners();
    }
  }

  Future<void> refreshConversation() async {
    if (conversation == null) return;
    try {
      final apiServer = await bind.mainGetApiServer();
      final resJson = await CercanoChatFfiBridge.getConversation(
        apiServer: apiServer,
        conversationId: conversation!.id,
      );
      final parsed = jsonDecode(resJson);
      if (parsed['error'] == null) {
        final next = ChatConversation.fromJson(parsed);
        technicianNotice =
            reassignmentNotice(conversation, next, branding.organizationName) ??
                technicianNotice;
        conversation = next;
        notifyListeners();
      }
    } catch (_) {}
  }

  bool isMessageRead(ChatMessage msg) {
    if (conversation?.otherLastReadAt == null) return false;
    try {
      final readAt = DateTime.parse(conversation!.otherLastReadAt!);
      final msgAt = DateTime.parse(msg.createdAt);
      return readAt.isAfter(msgAt) || readAt.isAtSameMomentAs(msgAt);
    } catch (_) {
      return false;
    }
  }
}
