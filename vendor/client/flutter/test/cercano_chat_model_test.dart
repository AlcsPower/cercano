// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_hbb/cercano_chat/cercano_chat_model.dart';

void main() {
  group('Cercano Chat Model Tests', () {
    test('ChatBranding defaults and fromJson', () {
      final defaultBranding = ChatBranding.defaultBranding();
      expect(defaultBranding.supportName, equals('Cercano Soporte'));
      expect(defaultBranding.accentColor, equals('#3B5BFF'));

      final customJson = {
        'support_name': 'Soporte TI Central',
        'organization_name': 'Organización',
        'logo_url': 'https://cercano.local/logo.png',
        'accent_color': '#FF5500',
        'welcome_text': 'Bienvenido a soporte',
        'info_text': 'Atención en horario laboral',
        'privacy_text': 'Confidencial',
      };
      final custom = ChatBranding.fromJson(customJson);
      expect(custom.supportName, equals('Soporte TI Central'));
      expect(custom.logoUrl, equals('https://cercano.local/logo.png'));
      expect(custom.accentColor, equals('#FF5500'));
    });

    test('ChatAttachment detects image MIME and filename extension', () {
      final imgAttachment = ChatAttachment.fromJson({
        'id': 'att-1',
        'name': 'screenshot.png',
        'mime': 'image/png',
        'size_bytes': 1024,
        'sha256': 'abc123hash',
      });
      expect(imgAttachment.isImage, isTrue);

      final pdfAttachment = ChatAttachment.fromJson({
        'id': 'att-2',
        'name': 'documento.pdf',
        'mime': 'application/pdf',
        'size_bytes': 2048,
        'sha256': 'def456hash',
      });
      expect(pdfAttachment.isImage, isFalse);
    });

    test('ChatMessage distinguishes sender types and read receipts', () {
      final clientMsg = ChatMessage.fromJson({
        'id': 'm-1',
        'conversation_id': 'c-1',
        'sender_type': 'device',
        'sender_id': 'dev-1',
        'body': 'Hola tengo un problema',
        'created_at': '2026-11-16T10:00:00Z',
      });
      expect(clientMsg.isMine, isTrue);
      expect(clientMsg.isSystem, isFalse);

      final techMsg = ChatMessage.fromJson({
        'id': 'm-2',
        'conversation_id': 'c-1',
        'sender_type': 'technician',
        'sender_id': 'u-2',
        'sender_name': 'Técnico Juan',
        'body': 'En qué puedo ayudarle',
        'created_at': '2026-11-16T10:01:00Z',
      });
      expect(techMsg.isMine, isFalse);
      expect(techMsg.senderName, equals('Técnico Juan'));

      final systemMsg = ChatMessage.fromJson({
        'id': 'm-3',
        'conversation_id': 'c-1',
        'sender_type': 'system',
        'sender_id': 'system',
        'body': 'Conversación asignada',
        'created_at': '2026-11-16T10:01:30Z',
      });
      expect(systemMsg.isSystem, isTrue);
    });

    test('ChatConversation parses status and read receipts calculation', () {
      final convJson = {
        'id': 'c-1',
        'device_id': 'dev-1',
        'status': 'assigned',
        'contact_first_name': 'Maria',
        'contact_last_name': 'Lopez',
        'assigned_user_id': 'u-2',
        'assigned_display_name': 'Tecnico 2',
        'other_last_read_at': '2026-11-16T10:05:00Z',
        'created_at': '2026-11-16T10:00:00Z',
        'updated_at': '2026-11-16T10:05:00Z',
        'messages': [
          {
            'id': 'm-1',
            'conversation_id': 'c-1',
            'sender_type': 'device',
            'sender_id': 'dev-1',
            'body': 'Mensaje leido',
            'created_at': '2026-11-16T10:02:00Z',
          },
          {
            'id': 'm-2',
            'conversation_id': 'c-1',
            'sender_type': 'device',
            'sender_id': 'dev-1',
            'body': 'Mensaje aun no leido',
            'created_at': '2026-11-16T10:06:00Z',
          }
        ]
      };

      final conv = ChatConversation.fromJson(convJson);
      expect(conv.status, equals('assigned'));
      expect(conv.isAssigned, isTrue);
      expect(conv.isClosed, isFalse);
      expect(conv.messages.length, equals(2));

      final model = CercanoChatModel();
      model.conversation = conv;

      expect(model.isMessageRead(conv.messages[0]), isTrue);
      expect(model.isMessageRead(conv.messages[1]), isFalse);
    });

    // F4.5-17: nombre visible del técnico, respaldo y aviso de reasignación.
    test('Technician display name, fallback and reassignment notice', () {
      ChatConversation conv(String? userId, String? name) =>
          ChatConversation.fromJson({
            'id': 'c-1',
            'status': 'assigned',
            'assigned_user_id': userId,
            'assigned_display_name': name,
            // El servidor ya no lo envía; aunque llegara, no se usa.
            'assigned_username': 'login_secreto',
          });

      expect(conv('u-1', 'Juan Pérez').assignedDisplayName, equals('Juan Pérez'));
      expect(technicianLabel('Juan Pérez', 'Acme'), equals('Juan Pérez'));
      expect(technicianLabel(null, 'Acme'), equals('un técnico de Acme'));
      expect(technicianLabel('  ', 'Acme'), equals('un técnico de Acme'));

      expect(reassignmentNotice(null, conv('u-1', 'Juan'), 'Acme'), isNull);
      expect(reassignmentNotice(conv('u-1', 'Juan'), conv('u-1', 'Juan'), 'Acme'),
          isNull);
      expect(reassignmentNotice(conv('u-1', 'Juan'), conv('u-2', 'Ana'), 'Acme'),
          equals('Ahora te atiende Ana'));
      expect(reassignmentNotice(conv('u-1', 'Juan'), conv('u-2', null), 'Acme'),
          equals('Ahora te atiende un técnico de Acme'));

      final model = CercanoChatModel();
      model.conversation = conv('u-1', null);
      expect(model.assignedTechnicianLabel, isNot(contains('login_secreto')));
    });
  });
}
