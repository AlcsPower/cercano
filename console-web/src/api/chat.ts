// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import { apiClient } from './client';
import {
  ChatAgent,
  ChatBranding,
  ChatConversation,
  ChatConversationDetail,
  ChatMessage,
  ChatStatus,
  ChatSummary,
} from '../types';

export type ChatFilter = 'all' | 'waiting' | 'mine' | 'active' | 'closed';

const DEFAULT_BRANDING: ChatBranding = {
  organization_name: 'Soporte interno',
  support_name: 'Cercano Soporte',
  logo_url: null,
  accent_color: '#3B5BFF',
  welcome_text: 'Cuéntanos qué necesitas y un técnico te atenderá.',
  info_text: 'Está conversando con el equipo de soporte.',
  privacy_text: 'Su conversación es privada y se guarda para seguimiento.',
};

let mockBranding: ChatBranding = { ...DEFAULT_BRANDING };

const minutesAgo = (minutes: number) =>
  new Date(Date.now() - minutes * 60_000).toISOString();

let mockConversations: ChatConversation[] = [
  {
    id: 'c-1',
    device_id: '123456789',
    device_name: 'PC-RECEPCION',
    device_hostname: 'WS-RECEPCION',
    device_os: 'Windows 11 Pro',
    status: 'waiting',
    assigned_user_id: null,
    assigned_username: null,
    contact_first_name: 'Ana',
    contact_last_name: 'Pérez',
    created_at: minutesAgo(14),
    updated_at: minutesAgo(2),
    last_message_at: minutesAgo(2),
    last_message_preview: 'No puedo imprimir desde ayer.',
    unread_count: 2,
  },
  {
    id: 'c-2',
    device_id: '987654321',
    device_name: 'WS-CONTABILIDAD',
    device_hostname: 'WS-CONTABILIDAD',
    device_os: 'Windows 10 Enterprise',
    status: 'active',
    assigned_user_id: 'me',
    assigned_username: 'Tú',
    contact_first_name: 'Carlos',
    contact_last_name: 'Ruiz',
    created_at: minutesAgo(40),
    updated_at: minutesAgo(5),
    last_message_at: minutesAgo(5),
    last_message_preview: 'Gracias, ya funciona.',
    unread_count: 0,
  },
  {
    id: 'c-3',
    device_id: '456789123',
    device_name: 'LAPTOP-DIRECCION',
    device_hostname: 'LAPTOP-DIRECCION',
    device_os: 'Windows 11 Pro',
    status: 'active',
    assigned_user_id: 'u-2',
    assigned_username: 'Técnico 2',
    contact_first_name: 'María',
    contact_last_name: 'López',
    created_at: minutesAgo(80),
    updated_at: minutesAgo(12),
    last_message_at: minutesAgo(12),
    last_message_preview: '¿Puede revisar el correo institucional?',
    unread_count: 1,
  },
  {
    id: 'c-4',
    device_id: '321654987',
    device_name: 'POS-MOSTRADOR',
    device_hostname: 'POS-MOSTRADOR',
    device_os: 'Windows 10 LTSC',
    status: 'closed',
    assigned_user_id: 'me',
    assigned_username: 'Tú',
    contact_first_name: 'José',
    contact_last_name: 'Martínez',
    created_at: minutesAgo(180),
    updated_at: minutesAgo(100),
    last_message_at: minutesAgo(100),
    last_message_preview: 'Resuelto, gracias.',
    unread_count: 0,
  },
];

const message = (
  conversationId: string,
  id: string,
  sender: ChatMessage['sender_type'],
  senderName: string,
  body: string,
  minutes: number
): ChatMessage => ({
  id,
  conversation_id: conversationId,
  sender_type: sender,
  sender_id: sender === 'technician' ? 'me' : 'device',
  sender_name: senderName,
  body,
  attachment: null,
  created_at: minutesAgo(minutes),
});

let mockMessages: Record<string, ChatMessage[]> = {
  'c-1': [
    message('c-1', 'm-1', 'client', 'Ana Pérez', 'Buenos días, no puedo imprimir desde ayer.', 14),
    message('c-1', 'm-2', 'system', 'Sistema', 'Conversación en espera de un técnico.', 14),
    message('c-1', 'm-3', 'client', 'Ana Pérez', 'Me sale un error al conectar con la impresora.', 2),
  ],
  'c-2': [
    message('c-2', 'm-4', 'client', 'Carlos Ruiz', 'Buenas, no podía entrar al sistema.', 40),
    message('c-2', 'm-5', 'technician', 'Tú', 'Prueba reiniciando la sesión, por favor.', 30),
    message('c-2', 'm-6', 'client', 'Carlos Ruiz', 'Gracias, ya funciona.', 5),
  ],
  'c-3': [
    message('c-3', 'm-7', 'client', 'María López', '¿Puede revisar el correo institucional?', 80),
    message('c-3', 'm-8', 'technician', 'Técnico 2', 'Claro, reviso el servidor y te confirmo.', 12),
  ],
  'c-4': [
    message('c-4', 'm-9', 'client', 'José Martínez', 'El terminal no abría el turno.', 180),
    message('c-4', 'm-10', 'technician', 'Tú', 'Quedó corregido, cierro la conversación.', 110),
    message('c-4', 'm-11', 'system', 'Sistema', 'Conversación cerrada.', 100),
  ],
};

const mockAgents: ChatAgent[] = [
  { id: 'me', username: 'Tú' },
  { id: 'u-2', username: 'Técnico 2' },
  { id: 'u-3', username: 'Técnico 3' },
];

const isLive = () => apiClient.isLiveMode() && Boolean(apiClient.getToken());

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = apiClient.getToken();
  const headers: Record<string, string> = {
    ...(init.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...((init.headers as Record<string, string>) || {}),
  };
  const response = await fetch(path, { ...init, headers });
  if (!response.ok) {
    let errorMessage = `Error ${response.status}`;
    try {
      const body = await response.json();
      errorMessage = body?.message || body?.error || errorMessage;
    } catch {
      // non-JSON error
    }
    throw new Error(errorMessage);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return response.json();
}

const matchesQuery = (conversation: ChatConversation, query: string) => {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return [
    conversation.device_name,
    conversation.device_hostname,
    conversation.contact_first_name,
    conversation.contact_last_name,
  ]
    .filter(Boolean)
    .some((value) => String(value).toLowerCase().includes(q));
};

const filterMock = (filter: ChatFilter, query: string): ChatConversation[] => {
  const sorted = [...mockConversations].sort((a, b) =>
    (b.last_message_at || b.created_at).localeCompare(a.last_message_at || a.created_at)
  );
  return sorted.filter((conversation) => {
    if (!matchesQuery(conversation, query)) return false;
    if (filter === 'waiting') return conversation.status === 'waiting';
    if (filter === 'mine')
      return conversation.assigned_user_id === 'me' && conversation.status !== 'closed';
    if (filter === 'active')
      return conversation.status === 'assigned' || conversation.status === 'active';
    if (filter === 'closed') return conversation.status === 'closed';
    return true;
  });
};

const updateMockConversation = (
  id: string,
  patch: Partial<ChatConversation>
): ChatConversation => {
  const index = mockConversations.findIndex((conversation) => conversation.id === id);
  if (index === -1) {
    throw new Error('Conversación no encontrada.');
  }
  mockConversations[index] = { ...mockConversations[index], ...patch, updated_at: new Date().toISOString() };
  return mockConversations[index];
};

const appendMockMessage = (messageToAdd: ChatMessage) => {
  mockMessages[messageToAdd.conversation_id] = [
    ...(mockMessages[messageToAdd.conversation_id] || []),
    messageToAdd,
  ];
  updateMockConversation(messageToAdd.conversation_id, {
    last_message_at: messageToAdd.created_at,
    last_message_preview: messageToAdd.body || '[adjunto]',
    updated_at: messageToAdd.created_at,
  });
};

export const chatApi = {
  async getConversations(filter: ChatFilter, query: string): Promise<ChatConversation[]> {
    if (!isLive()) {
      return filterMock(filter, query);
    }
    const params = new URLSearchParams();
    if (filter === 'waiting' || filter === 'active' || filter === 'closed') {
      params.set('status', filter);
    }
    if (filter === 'mine') {
      params.set('assigned', 'me');
    }
    if (query.trim()) {
      params.set('q', query.trim());
    }
    const data = await request<{ conversations: ChatConversation[] }>(
      `/api/chat/conversations?${params.toString()}`
    );
    return data.conversations || [];
  },

  async getConversation(id: string): Promise<ChatConversationDetail> {
    if (!isLive()) {
      const conversation = mockConversations.find((item) => item.id === id);
      if (!conversation) throw new Error('Conversación no encontrada.');
      return {
        ...conversation,
        messages: mockMessages[id] || [],
        closed_at: conversation.status === 'closed' ? conversation.updated_at : null,
        closed_by: conversation.status === 'closed' ? 'me' : null,
        next_before: null,
        other_last_read_at: null,
      };
    }
    return request<ChatConversationDetail>(`/api/chat/conversations/${id}`);
  },

  async claim(id: string): Promise<ChatConversation> {
    if (!isLive()) {
      return updateMockConversation(id, {
        status: 'assigned',
        assigned_user_id: 'me',
        assigned_username: 'Tú',
      });
    }
    return request<ChatConversation>(`/api/chat/conversations/${id}/claim`, { method: 'POST' });
  },

  async release(id: string): Promise<ChatConversation> {
    if (!isLive()) {
      return updateMockConversation(id, {
        status: 'waiting',
        assigned_user_id: null,
        assigned_username: null,
      });
    }
    return request<ChatConversation>(`/api/chat/conversations/${id}/release`, { method: 'POST' });
  },

  async close(id: string): Promise<ChatConversation> {
    if (!isLive()) {
      return updateMockConversation(id, { status: 'closed' });
    }
    return request<ChatConversation>(`/api/chat/conversations/${id}/close`, {
      method: 'POST',
      body: JSON.stringify({ reason: 'resolved' }),
    });
  },

  async reopen(id: string): Promise<ChatConversation> {
    if (!isLive()) {
      return updateMockConversation(id, {
        status: 'waiting',
        assigned_user_id: null,
        assigned_username: null,
      });
    }
    return request<ChatConversation>(`/api/chat/conversations/${id}/reopen`, { method: 'POST' });
  },

  async sendMessage(id: string, body: string): Promise<ChatMessage> {
    if (!isLive()) {
      const messageToAdd: ChatMessage = {
        id: `m-${crypto.randomUUID()}`,
        conversation_id: id,
        sender_type: 'technician',
        sender_id: 'me',
        sender_name: 'Tú',
        body,
        attachment: null,
        created_at: new Date().toISOString(),
      };
      appendMockMessage(messageToAdd);
      return messageToAdd;
    }
    return request<ChatMessage>(`/api/chat/conversations/${id}/messages`, {
      method: 'POST',
      body: JSON.stringify({ body }),
    });
  },

  async sendAttachment(id: string, file: File): Promise<ChatMessage> {
    if (!isLive()) {
      const messageToAdd: ChatMessage = {
        id: `m-${crypto.randomUUID()}`,
        conversation_id: id,
        sender_type: 'technician',
        sender_id: 'me',
        sender_name: 'Tú',
        body: '',
        attachment: {
          id: `att-${crypto.randomUUID()}`,
          name: file.name,
          mime: file.type || 'application/octet-stream',
          size_bytes: file.size,
          sha256: '',
        },
        created_at: new Date().toISOString(),
      };
      appendMockMessage(messageToAdd);
      return messageToAdd;
    }
    const token = apiClient.getToken();
    const response = await fetch(`/api/chat/conversations/${id}/attachments`, {
      method: 'POST',
      headers: {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        'Content-Type': file.type || 'application/octet-stream',
        'X-File-Name-B64': btoa(
          Array.from(new TextEncoder().encode(file.name))
            .map((byte) => String.fromCharCode(byte))
            .join('')
        ),
        'X-Client-Message-Id': crypto.randomUUID(),
      },
      body: file,
    });
    if (!response.ok) {
      throw new Error(`No se pudo subir el adjunto (${response.status}).`);
    }
    return response.json();
  },

  async markRead(id: string): Promise<void> {
    if (!isLive()) {
      updateMockConversation(id, { unread_count: 0 });
      return;
    }
    await request<void>(`/api/chat/conversations/${id}/read`, { method: 'POST' });
  },

  async escalate(
    id: string,
    traceId?: string
  ): Promise<{ device_id: string; trace_id: string; url: string }> {
    if (!isLive()) {
      const conv = mockConversations.find((c) => c.id === id);
      const deviceId = conv?.device_id || '987654321';
      const actualTrace = traceId || id;
      return {
        device_id: deviceId,
        trace_id: actualTrace,
        url: `cercano://connect?device=${deviceId}&trace=${actualTrace}`,
      };
    }
    return request<{ device_id: string; trace_id: string; url: string }>(
      `/api/chat/conversations/${id}/escalate`,
      {
        method: 'POST',
        body: JSON.stringify({ trace_id: traceId }),
      }
    );
  },

  async getBranding(): Promise<ChatBranding> {
    if (!isLive()) {
      return { ...mockBranding };
    }
    return request<ChatBranding>('/api/chat/branding');
  },

  async updateBranding(branding: ChatBranding): Promise<ChatBranding> {
    if (!isLive()) {
      mockBranding = { ...branding };
      return { ...mockBranding };
    }
    return request<ChatBranding>('/api/chat/branding', {
      method: 'PUT',
      body: JSON.stringify(branding),
    });
  },

  async getAgents(): Promise<ChatAgent[]> {
    if (!isLive()) {
      return [...mockAgents];
    }
    const data = await request<{ agents: ChatAgent[] }>('/api/chat/agents');
    return data.agents || [];
  },

  async getSummary(): Promise<ChatSummary> {
    if (!isLive()) {
      const open = mockConversations.filter((conversation) => conversation.status !== 'closed');
      return {
        waiting: open.filter((conversation) => conversation.status === 'waiting').length,
        assigned_to_me: open.filter((conversation) => conversation.assigned_user_id === 'me').length,
        active: open.filter(
          (conversation) => conversation.status === 'assigned' || conversation.status === 'active'
        ).length,
        unread: open.reduce((total, conversation) => total + conversation.unread_count, 0),
      };
    }
    return request<ChatSummary>('/api/chat/summary');
  },
};

export const chatStatusLabel = (status: ChatStatus): string => {
  switch (status) {
    case 'waiting':
      return 'En espera';
    case 'assigned':
      return 'Asignada';
    case 'active':
      return 'Activa';
    case 'closed':
      return 'Cerrada';
  }
};
