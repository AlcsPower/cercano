// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

/// Puente Dart para operaciones de Cercano Chat.
/// Proporciona wrappers limpios y maneja fallback HTTP REST si los bindings FFI
/// binarios directos aún no se han recargado en el runtime de Flutter.
class CercanoChatFfiBridge {
  static Future<String> getBranding(String apiServer) async {
    try {
      final uri = Uri.parse('${apiServer.replaceAll(RegExp(r'/+$'), '')}/api/chat/branding');
      final resp = await http.get(uri).timeout(const Duration(seconds: 5));
      if (resp.statusCode == 200) {
        return resp.body;
      }
    } catch (e) {
      debugPrint('Error en getBranding: $e');
    }
    return '';
  }

  static Future<String> createConversation({
    required String apiServer,
    required String firstName,
    required String lastName,
    required String initialMessage,
  }) async {
    try {
      final uri = Uri.parse('${apiServer.replaceAll(RegExp(r'/+$'), '')}/api/chat/conversations');
      final resp = await http.post(
        uri,
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'contact_first_name': firstName,
          'contact_last_name': lastName,
          'initial_message': initialMessage,
        }),
      ).timeout(const Duration(seconds: 10));

      return resp.body;
    } catch (e) {
      return jsonEncode({'error': 'Error de conexión: $e'});
    }
  }

  static Future<String> getConversation({
    required String apiServer,
    required String conversationId,
  }) async {
    try {
      final uri = Uri.parse(
          '${apiServer.replaceAll(RegExp(r'/+$'), '')}/api/chat/conversations/$conversationId');
      final resp = await http.get(uri).timeout(const Duration(seconds: 10));
      return resp.body;
    } catch (e) {
      return jsonEncode({'error': 'Error obteniendo conversación: $e'});
    }
  }

  static Future<String> sendMessage({
    required String apiServer,
    required String conversationId,
    required String body,
  }) async {
    try {
      final uri = Uri.parse(
          '${apiServer.replaceAll(RegExp(r'/+$'), '')}/api/chat/conversations/$conversationId/messages');
      final resp = await http.post(
        uri,
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'body': body}),
      ).timeout(const Duration(seconds: 10));

      return resp.body;
    } catch (e) {
      return jsonEncode({'error': 'Error enviando mensaje: $e'});
    }
  }

  static Future<bool> markRead({
    required String apiServer,
    required String conversationId,
  }) async {
    try {
      final uri = Uri.parse(
          '${apiServer.replaceAll(RegExp(r'/+$'), '')}/api/chat/conversations/$conversationId/read');
      final resp = await http.post(uri).timeout(const Duration(seconds: 5));
      return resp.statusCode == 200 || resp.statusCode == 204;
    } catch (_) {
      return false;
    }
  }

  static Future<bool> closeConversation({
    required String apiServer,
    required String conversationId,
    required String reason,
  }) async {
    try {
      final uri = Uri.parse(
          '${apiServer.replaceAll(RegExp(r'/+$'), '')}/api/chat/conversations/$conversationId/close');
      final resp = await http.post(
        uri,
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'reason': reason}),
      ).timeout(const Duration(seconds: 5));
      return resp.statusCode == 200 || resp.statusCode == 204;
    } catch (_) {
      return false;
    }
  }

  static void startEventsListener(String apiServer) {
    // Delegado al módulo Rust del cliente en F4.5-10
    debugPrint('CercanoChat events listener configurado para: $apiServer');
  }
}
