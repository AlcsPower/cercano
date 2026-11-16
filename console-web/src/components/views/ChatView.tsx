// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  ArrowLeft,
  Bell,
  BellOff,
  Check,
  CheckCheck,
  CheckCircle2,
  Inbox,
  Lock,
  MessageCircle,
  Paperclip,
  RefreshCw,
  Search,
  Send,
  Settings2,
  ShieldCheck,
  UserRound,
  WifiOff,
} from 'lucide-react';
import { apiClient } from '../../api/client';
import { chatApi, chatStatusLabel, ChatFilter } from '../../api/chat';
import {
  ChatBranding,
  ChatConversation,
  ChatConversationDetail,
  ChatMessage,
} from '../../types';
import { AppleCard } from '../common/AppleCard';
import { AppleButton } from '../common/AppleButton';
import { StatusPill } from '../common/StatusPill';
import { ChatBrandingForm } from '../chat/ChatBrandingForm';

interface ChatViewProps {
  currentUserId: string;
  canManageBranding: boolean;
}

const DEFAULT_BRANDING: ChatBranding = {
  support_name: 'Cercano Soporte',
  organization_name: 'Soporte interno',
  logo_url: null,
  accent_color: '#3B5BFF',
  welcome_text: 'Cuéntanos qué necesitas y un técnico te atenderá.',
  info_text: 'Está conversando con el equipo de soporte.',
  privacy_text: 'Su conversación es privada y se guarda para seguimiento.',
};

const FILTERS: { id: ChatFilter; label: string }[] = [
  { id: 'all', label: 'Todas' },
  { id: 'waiting', label: 'En espera' },
  { id: 'mine', label: 'Mías' },
  { id: 'active', label: 'Activas' },
  { id: 'closed', label: 'Cerradas' },
];

const displayName = (conversation?: ChatConversation | null): string => {
  if (!conversation) return 'Conversación';
  const contact = [conversation.contact_first_name, conversation.contact_last_name]
    .filter(Boolean)
    .join(' ');
  return contact || conversation.device_name || conversation.device_id;
};

const formatTime = (iso?: string | null): string => {
  if (!iso) return '';
  return new Intl.DateTimeFormat('es', {
    hour: '2-digit',
    minute: '2-digit',
  }).format(new Date(iso));
};

const formatRelative = (iso?: string | null): string => {
  if (!iso) return '';
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return 'Ahora';
  if (seconds < 3600) return `Hace ${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `Hace ${Math.floor(seconds / 3600)}h`;
  return `Hace ${Math.floor(seconds / 86400)}d`;
};

const statusPill = (status: ChatConversation['status']) => {
  if (status === 'waiting') return { status: 'idle' as const, label: chatStatusLabel(status) };
  if (status === 'closed') return { status: 'offline' as const, label: chatStatusLabel(status) };
  return { status: 'online' as const, label: chatStatusLabel(status) };
};

const formatSize = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

export const ChatView: React.FC<ChatViewProps> = ({ currentUserId, canManageBranding }) => {
  const [conversations, setConversations] = useState<ChatConversation[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<ChatConversationDetail | null>(null);
  const [filter, setFilter] = useState<ChatFilter>('all');
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [draft, setDraft] = useState('');
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [branding, setBranding] = useState<ChatBranding>(DEFAULT_BRANDING);
  const [brandingOpen, setBrandingOpen] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  type SseStatus = 'connected' | 'connecting' | 'reconnecting' | 'offline';
  const [sseStatus, setSseStatus] = useState<SseStatus>('connecting');
  const [notificationPermission, setNotificationPermission] = useState<NotificationPermission>(() => {
    if (typeof window !== 'undefined' && 'Notification' in window) {
      return Notification.permission;
    }
    return 'default';
  });

  const selectedIdRef = useRef<string | null>(selectedId);
  useEffect(() => {
    selectedIdRef.current = selectedId;
  }, [selectedId]);

  const requestNotificationPermission = async () => {
    if (typeof window === 'undefined' || !('Notification' in window)) return;
    try {
      const permission = await Notification.requestPermission();
      setNotificationPermission(permission);
    } catch {
      // Ignored
    }
  };

  const loadConversations = async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const list = await chatApi.getConversations('all', '');
      setConversations(list);
      setSelectedId((current) => {
        if (current && list.some((conversation) => conversation.id === current)) return current;
        return list[0]?.id || null;
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'No se pudieron cargar las conversaciones.');
    } finally {
      if (!silent) setLoading(false);
    }
  };

  const loadDetail = async (id: string, silent = false) => {
    if (!silent) setDetailLoading(true);
    try {
      const conversation = await chatApi.getConversation(id);
      setDetail(conversation);
      await chatApi.markRead(id);
      setConversations((current) =>
        current.map((item) => (item.id === id ? { ...item, unread_count: 0 } : item))
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'No se pudo abrir la conversación.');
    } finally {
      if (!silent) setDetailLoading(false);
    }
  };

  useEffect(() => {
    loadConversations();
    chatApi.getBranding().then(setBranding).catch(() => setBranding(DEFAULT_BRANDING));

    if (!apiClient.isLiveMode()) {
      setSseStatus('offline');
      const interval = setInterval(() => {
        loadConversations(true);
      }, 5000);
      return () => clearInterval(interval);
    }

    const token = apiClient.getToken();
    if (!token) {
      setSseStatus('offline');
      return;
    }

    setSseStatus('connecting');
    const sseUrl = `/api/chat/events?token=${encodeURIComponent(token)}`;
    const eventSource = new EventSource(sseUrl);

    eventSource.onopen = () => {
      setSseStatus('connected');
    };

    eventSource.onerror = () => {
      setSseStatus('reconnecting');
    };

    eventSource.addEventListener('poke', (e: MessageEvent) => {
      try {
        const poke = JSON.parse(e.data);
        if (poke.type === 'resync') {
          loadConversations(true);
          const activeId = selectedIdRef.current;
          if (activeId) loadDetail(activeId, true);
        } else if (poke.type === 'queue') {
          loadConversations(true);
        } else if (poke.type === 'status') {
          loadConversations(true);
          const activeId = selectedIdRef.current;
          if (activeId && activeId === poke.conversation_id) loadDetail(activeId, true);
        } else if (poke.type === 'message') {
          loadConversations(true);
          const activeId = selectedIdRef.current;
          if (activeId && activeId === poke.conversation_id) {
            loadDetail(activeId, true);
          }

          // Browser notification when tab is backgrounded
          if (
            typeof document !== 'undefined' &&
            document.hidden &&
            typeof Notification !== 'undefined' &&
            Notification.permission === 'granted'
          ) {
            try {
              const notif = new Notification('Cercano Soporte: Nuevo mensaje', {
                body: 'Hay nueva actividad en la cola de soporte.',
                icon: '/favicon.ico',
                tag: 'cercano-chat-poke',
              });
              notif.onclick = () => {
                window.focus();
                if (poke.conversation_id) {
                  setSelectedId(poke.conversation_id);
                }
                notif.close();
              };
            } catch {
              // Platform restrictions
            }
          }
        }
      } catch {
        // Ignored
      }
    });

    // Fallback safety refresh every 60s
    const safetyInterval = setInterval(() => {
      loadConversations(true);
    }, 60000);

    return () => {
      eventSource.close();
      clearInterval(safetyInterval);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (selectedId) {
      loadDetail(selectedId);
    } else {
      setDetail(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ block: 'end' });
  }, [detail?.messages.length]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return conversations.filter((conversation) => {
      const contact = [conversation.contact_first_name, conversation.contact_last_name]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      const matchesQuery =
        !q ||
        contact.includes(q) ||
        (conversation.device_name || '').toLowerCase().includes(q) ||
        (conversation.device_hostname || '').toLowerCase().includes(q);
      if (!matchesQuery) return false;
      if (filter === 'waiting') return conversation.status === 'waiting';
      if (filter === 'mine') {
        return (
          conversation.assigned_user_id === currentUserId ||
          conversation.assigned_username === 'Tú'
        ) && conversation.status !== 'closed';
      }
      if (filter === 'active') {
        return conversation.status === 'assigned' || conversation.status === 'active';
      }
      if (filter === 'closed') return conversation.status === 'closed';
      return true;
    });
  }, [conversations, query, filter, currentUserId]);

  const counts = useMemo(() => {
    const open = conversations.filter((conversation) => conversation.status !== 'closed');
    return {
      waiting: open.filter((conversation) => conversation.status === 'waiting').length,
      mine: open.filter(
        (conversation) =>
          conversation.assigned_user_id === currentUserId ||
          conversation.assigned_username === 'Tú'
      ).length,
      active: open.filter(
        (conversation) =>
          conversation.status === 'assigned' || conversation.status === 'active'
      ).length,
      closed: conversations.filter((conversation) => conversation.status === 'closed').length,
      unread: open.reduce((total, conversation) => total + conversation.unread_count, 0),
    };
  }, [conversations, currentUserId]);

  const selectedConversation =
    detail || conversations.find((conversation) => conversation.id === selectedId) || null;
  const isClosed = selectedConversation?.status === 'closed';
  const live = apiClient.isLiveMode();

  const runAction = async (action: () => Promise<unknown>) => {
    setError(null);
    try {
      await action();
      await loadConversations(true);
      if (selectedId) await loadDetail(selectedId, true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'No se pudo completar la acción.');
    }
  };

  const handleSend = async () => {
    if (!selectedId || !draft.trim() || sending || isClosed) return;
    setSending(true);
    setError(null);
    try {
      await chatApi.sendMessage(selectedId, draft.trim());
      setDraft('');
      await loadDetail(selectedId, true);
      await loadConversations(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'No se pudo enviar el mensaje.');
    } finally {
      setSending(false);
    }
  };

  const handleAttachment = async (file: File | undefined) => {
    if (!file || !selectedId || sending || isClosed) return;
    setSending(true);
    setError(null);
    try {
      await chatApi.sendAttachment(selectedId, file);
      await loadDetail(selectedId, true);
      await loadConversations(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'No se pudo enviar el adjunto.');
    } finally {
      setSending(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const handleComposerKeyDown = (event: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      handleSend();
    }
  };

  const isMine = (message: ChatMessage) => message.sender_type === 'technician';
  const isRead = (message: ChatMessage) =>
    Boolean(
      detail?.other_last_read_at &&
        new Date(detail.other_last_read_at).getTime() >= new Date(message.created_at).getTime()
    );

  return (
    <div className="space-y-5 animate-fade-in">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-extrabold tracking-apple-display text-cercano-night dark:text-white">
            Conversaciones
          </h1>
          <p className="text-sm text-cercano-slate dark:text-gray-400 mt-1">
            Atención de problemas pequeños por chat; escala a sesión remota cuando haga falta.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {!live ? (
            <span className="text-xs px-2.5 py-1 rounded-full bg-amber-500/10 text-amber-700 dark:text-amber-400 border border-amber-500/20">
              Datos de ejemplo
            </span>
          ) : sseStatus === 'connected' ? (
            <span
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20"
              title="Conexión en tiempo real activa"
              aria-label="En tiempo real"
            >
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse motion-reduce:animate-none" />
              <span className="hidden sm:inline">En vivo</span>
            </span>
          ) : sseStatus === 'reconnecting' || sseStatus === 'connecting' ? (
            <span
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-amber-500/10 text-amber-700 dark:text-amber-400 border border-amber-500/20"
              title="Reconectando con el servidor"
              aria-label="Reconectando"
            >
              <RefreshCw size={12} className="animate-spin motion-reduce:animate-none" />
              <span>Reconectando</span>
            </span>
          ) : (
            <span
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-red-500/10 text-red-700 dark:text-red-400 border border-red-500/20"
              title="Sin conexión en tiempo real"
              aria-label="Desconectado"
            >
              <WifiOff size={12} />
              <span>Desconectado</span>
            </span>
          )}

          {typeof window !== 'undefined' && 'Notification' in window && (
            notificationPermission === 'default' ? (
              <AppleButton
                variant="secondary"
                size="sm"
                onClick={requestNotificationPermission}
                icon={<Bell size={14} />}
                aria-label="Activar notificaciones de escritorio"
              >
                Notificaciones
              </AppleButton>
            ) : notificationPermission === 'granted' ? (
              <span
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-cercano-blue/10 text-cercano-blue dark:text-blue-400 border border-cercano-blue/20"
                title="Notificaciones de escritorio activadas"
                aria-label="Notificaciones activadas"
              >
                <Bell size={13} />
                <span className="hidden sm:inline">Alertas on</span>
              </span>
            ) : (
              <span
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-black/5 dark:bg-white/10 text-cercano-slate dark:text-gray-400 border border-black/5 dark:border-white/10"
                title="Notificaciones bloqueadas por el navegador"
                aria-label="Notificaciones bloqueadas"
              >
                <BellOff size={13} />
                <span className="hidden sm:inline">Silenciado</span>
              </span>
            )
          )}

          {canManageBranding && (
            <AppleButton
              variant="secondary"
              size="sm"
              onClick={() => setBrandingOpen(true)}
              icon={<Settings2 size={14} />}
            >
              Marca
            </AppleButton>
          )}
          <AppleButton
            variant="secondary"
            size="sm"
            onClick={() => {
              loadConversations();
              if (selectedId) loadDetail(selectedId);
            }}
            icon={<RefreshCw size={14} className={loading ? 'animate-spin motion-reduce:animate-none' : ''} />}
          >
            Actualizar
          </AppleButton>
        </div>
      </div>

      {live && sseStatus === 'reconnecting' && (
        <div
          role="status"
          aria-live="polite"
          className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-2xl border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-800 dark:text-amber-300"
        >
          <div className="flex items-center gap-2">
            <RefreshCw size={16} className="animate-spin motion-reduce:animate-none text-amber-600 dark:text-amber-400 shrink-0" />
            <span>Reconectando al servicio de chat en tiempo real… Las actualizaciones se reflejarán automáticamente al restablecer el enlace.</span>
          </div>
          <AppleButton
            size="sm"
            variant="secondary"
            onClick={() => {
              loadConversations();
              if (selectedId) loadDetail(selectedId);
            }}
          >
            Reintentar
          </AppleButton>
        </div>
      )}

      {error && (
        <div
          role="alert"
          className="rounded-2xl border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-700 dark:text-red-400"
        >
          {error}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        {FILTERS.map((item) => {
          const count =
            item.id === 'waiting'
              ? counts.waiting
              : item.id === 'mine'
              ? counts.mine
              : item.id === 'active'
              ? counts.active
              : item.id === 'closed'
              ? counts.closed
              : conversations.length;
          return (
            <button
              key={item.id}
              onClick={() => setFilter(item.id)}
              aria-pressed={filter === item.id}
              className={`btn-apple inline-flex items-center gap-2 rounded-xl px-3 py-1.5 text-xs font-semibold transition-colors ${
                filter === item.id
                  ? 'bg-cercano-blue text-white'
                  : 'bg-black/5 dark:bg-white/10 text-cercano-slate dark:text-gray-300 hover:bg-black/10 dark:hover:bg-white/15'
              }`}
            >
              {item.label}
              <span
                className={`rounded-full px-1.5 py-0.5 text-[10px] ${
                  filter === item.id ? 'bg-white/20 text-white' : 'bg-black/5 dark:bg-white/10'
                }`}
              >
                {count}
              </span>
            </button>
          );
        })}
        {counts.unread > 0 && (
          <span className="text-xs text-cercano-slate dark:text-gray-400">
            {counts.unread} sin leer
          </span>
        )}
      </div>

      <div className="grid gap-4 lg:grid-cols-[360px_1fr] items-start">
        <AppleCard className="p-0 overflow-hidden">
          <div className="p-3 border-b border-black/5 dark:border-white/[0.04]">
            <label className="relative block">
              <span className="sr-only">Buscar conversaciones</span>
              <Search
                size={16}
                className="absolute left-3 top-1/2 -translate-y-1/2 text-cercano-slate dark:text-gray-500"
              />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Buscar por nombre o equipo"
                className="w-full rounded-xl border border-black/10 dark:border-white/10 bg-white/70 dark:bg-zinc-800/70 py-2 pl-9 pr-3 text-sm outline-none focus-visible:ring-2 focus-visible:ring-cercano-blue/40"
              />
            </label>
          </div>

          <div className="max-h-[560px] overflow-y-auto">
            {loading ? (
              <div className="p-4 space-y-3">
                {[1, 2, 3].map((item) => (
                  <div key={item} className="h-16 rounded-xl bg-black/5 dark:bg-white/5 animate-pulse" />
                ))}
              </div>
            ) : filtered.length === 0 ? (
              <div className="p-8 text-center">
                <Inbox size={28} className="mx-auto text-cercano-slate dark:text-gray-500" />
                <p className="mt-2 text-sm font-medium text-cercano-night dark:text-white">
                  No hay conversaciones
                </p>
                <p className="text-xs text-cercano-slate dark:text-gray-400">
                  Cambia el filtro o espera a que alguien escriba.
                </p>
              </div>
            ) : (
              filtered.map((conversation) => {
                const pill = statusPill(conversation.status);
                const selected = conversation.id === selectedId;
                return (
                  <button
                    key={conversation.id}
                    onClick={() => setSelectedId(conversation.id)}
                    aria-current={selected ? 'true' : undefined}
                    aria-label={`Conversación con ${displayName(conversation)}, ${pill.label}`}
                    className={`w-full text-left px-4 py-3 border-b border-black/5 dark:border-white/[0.04] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cercano-blue focus-visible:ring-inset motion-reduce:transition-none ${
                      selected
                        ? 'bg-cercano-blue/10 dark:bg-cercano-blue/20'
                        : 'hover:bg-black/[0.03] dark:hover:bg-white/[0.04]'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <p className="text-sm font-semibold text-cercano-night dark:text-white truncate">
                          {displayName(conversation)}
                        </p>
                        <p className="text-xs text-cercano-slate dark:text-gray-400 truncate">
                          {conversation.device_name || conversation.device_id}
                        </p>
                      </div>
                      <span className="text-[11px] text-cercano-slate dark:text-gray-500 shrink-0">
                        {formatRelative(conversation.last_message_at)}
                      </span>
                    </div>
                    <div className="mt-1.5 flex items-center justify-between gap-2">
                      <p className="text-xs text-cercano-slate dark:text-gray-400 truncate">
                        {conversation.last_message_preview || 'Sin mensajes'}
                      </p>
                      <div className="flex items-center gap-1.5 shrink-0">
                        {conversation.unread_count > 0 && (
                          <span
                            className="min-w-[18px] h-[18px] px-1 rounded-full bg-cercano-blue text-white text-[10px] font-bold flex items-center justify-center"
                            aria-label={`${conversation.unread_count} sin leer`}
                          >
                            {conversation.unread_count}
                          </span>
                        )}
                        <StatusPill status={pill.status} label={pill.label} size="sm" />
                      </div>
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </AppleCard>

        <AppleCard className="p-0 overflow-hidden flex flex-col min-h-[560px]">
          {!selectedConversation ? (
            <div className="flex-1 flex flex-col items-center justify-center p-10 text-center">
              <MessageCircle size={36} className="text-cercano-slate dark:text-gray-500" />
              <p className="mt-3 text-base font-semibold text-cercano-night dark:text-white">
                Selecciona una conversación
              </p>
              <p className="text-sm text-cercano-slate dark:text-gray-400">
                La cola y el historial aparecen aquí.
              </p>
            </div>
          ) : (
            <>
              <div className="p-4 border-b border-black/5 dark:border-white/[0.04]">
                <div className="flex items-start gap-3">
                  <button
                    onClick={() => setSelectedId(null)}
                    className="lg:hidden p-2 rounded-full bg-black/5 dark:bg-white/10 text-cercano-slate dark:text-gray-300"
                    aria-label="Volver a la lista"
                  >
                    <ArrowLeft size={16} />
                  </button>
                  {branding.logo_url ? (
                    <img
                      src={branding.logo_url}
                      alt=""
                      className="w-10 h-10 rounded-2xl object-contain bg-white dark:bg-zinc-800 border border-black/5 dark:border-white/10"
                    />
                  ) : (
                    <div
                      className="w-10 h-10 rounded-2xl flex items-center justify-center text-white shrink-0"
                      style={{ backgroundColor: branding.accent_color }}
                    >
                      <MessageCircle size={18} />
                    </div>
                  )}
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <h2 className="text-lg font-bold text-cercano-night dark:text-white truncate">
                        {displayName(selectedConversation)}
                      </h2>
                      <StatusPill
                        status={statusPill(selectedConversation.status).status}
                        label={statusPill(selectedConversation.status).label}
                        size="sm"
                      />
                    </div>
                    <p className="text-xs text-cercano-slate dark:text-gray-400 truncate">
                      {selectedConversation.device_name || selectedConversation.device_id}
                      {selectedConversation.device_hostname
                        ? ` · ${selectedConversation.device_hostname}`
                        : ''}
                      {selectedConversation.device_os ? ` · ${selectedConversation.device_os}` : ''}
                    </p>
                  </div>
                </div>

                <div className="mt-3 flex flex-wrap gap-2">
                  {selectedConversation.status === 'waiting' && (
                    <AppleButton
                      size="sm"
                      onClick={() => runAction(() => chatApi.claim(selectedConversation.id))}
                    >
                      Reclamar
                    </AppleButton>
                  )}
                  {(selectedConversation.status === 'assigned' ||
                    selectedConversation.status === 'active') && (
                    <AppleButton
                      size="sm"
                      variant="secondary"
                      onClick={() => runAction(() => chatApi.release(selectedConversation.id))}
                    >
                      Liberar
                    </AppleButton>
                  )}
                  {!isClosed && (
                    <AppleButton
                      size="sm"
                      variant="secondary"
                      onClick={() => runAction(() => chatApi.close(selectedConversation.id))}
                    >
                      Cerrar
                    </AppleButton>
                  )}
                  {isClosed && canManageBranding && (
                    <AppleButton
                      size="sm"
                      variant="secondary"
                      onClick={() => runAction(() => chatApi.reopen(selectedConversation.id))}
                    >
                      Reabrir
                    </AppleButton>
                  )}
                </div>
              </div>

              <div className="px-4 py-2.5 bg-black/[0.02] dark:bg-white/[0.03] border-b border-black/5 dark:border-white/[0.04]">
                <p className="text-xs text-cercano-slate dark:text-gray-400 flex items-start gap-2">
                  <MessageCircle size={14} className="mt-0.5 shrink-0" />
                  {branding.info_text || DEFAULT_BRANDING.info_text}
                </p>
              </div>

              <div
                className="flex-1 overflow-y-auto p-4 space-y-3 bg-black/[0.01] dark:bg-black/10"
                aria-live="polite"
              >
                {detailLoading && !detail ? (
                  <div className="space-y-3">
                    {[1, 2, 3].map((item) => (
                      <div key={item} className="h-14 rounded-2xl bg-black/5 dark:bg-white/5 animate-pulse" />
                    ))}
                  </div>
                ) : (detail?.messages || []).length === 0 ? (
                  <p className="text-center text-sm text-cercano-slate dark:text-gray-400 py-10">
                    Todavía no hay mensajes.
                  </p>
                ) : (
                  (detail?.messages || []).map((message) => {
                    if (message.sender_type === 'system') {
                      return (
                        <p
                          key={message.id}
                          className="text-center text-xs text-cercano-slate dark:text-gray-500"
                        >
                          {message.body}
                        </p>
                      );
                    }
                    const mine = isMine(message);
                    return (
                      <div
                        key={message.id}
                        className={`flex items-end gap-2 ${mine ? 'justify-end' : 'justify-start'}`}
                      >
                        {!mine && (
                          <div className="w-7 h-7 rounded-full bg-cercano-blue/15 text-cercano-blue flex items-center justify-center shrink-0">
                            <UserRound size={14} />
                          </div>
                        )}
                        <div
                          className={`max-w-[75%] rounded-2xl px-3.5 py-2 text-sm ${
                            mine
                              ? 'bg-cercano-blue text-white rounded-br-md'
                              : 'bg-white dark:bg-zinc-800 text-cercano-night dark:text-white border border-black/5 dark:border-white/10 rounded-bl-md'
                          }`}
                        >
                          {!mine && message.sender_name && (
                            <p className="text-[11px] font-semibold opacity-70 mb-0.5">
                              {message.sender_name}
                            </p>
                          )}
                          {message.body && <p className="whitespace-pre-wrap break-words">{message.body}</p>}
                          {message.attachment && (
                            <div
                              className={`mt-1.5 flex items-center gap-2 rounded-xl px-2.5 py-2 text-xs ${
                                mine ? 'bg-white/15' : 'bg-black/5 dark:bg-white/10'
                              }`}
                            >
                              <Paperclip size={14} />
                              <span className="truncate">{message.attachment.name}</span>
                              <span className="opacity-70 shrink-0">
                                {formatSize(message.attachment.size_bytes)}
                              </span>
                            </div>
                          )}
                          <div
                            className={`mt-1 flex items-center justify-end gap-1 text-[10px] ${
                              mine ? 'text-white/70' : 'text-cercano-slate dark:text-gray-400'
                            }`}
                          >
                            <span>{formatTime(message.created_at)}</span>
                            {mine &&
                              (isRead(message) ? (
                                <CheckCheck size={12} aria-label="Leído" />
                              ) : (
                                <Check size={12} aria-label="Enviado" />
                              ))}
                          </div>
                        </div>
                      </div>
                    );
                  })
                )}
                <div ref={messagesEndRef} />
              </div>

              <div className="border-t border-black/5 dark:border-white/[0.04] p-3">
                {isClosed ? (
                  <p className="flex items-center justify-center gap-2 text-xs text-cercano-slate dark:text-gray-400 py-2">
                    <Lock size={14} /> Conversación cerrada.
                  </p>
                ) : (
                  <div className="flex items-end gap-2">
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept="image/png,image/jpeg,image/webp,application/pdf"
                      className="hidden"
                      onChange={(event) => handleAttachment(event.target.files?.[0])}
                    />
                    <button
                      type="button"
                      onClick={() => fileInputRef.current?.click()}
                      disabled={sending}
                      className="btn-apple p-2.5 rounded-xl bg-black/5 dark:bg-white/10 text-cercano-slate dark:text-gray-300 hover:bg-black/10 dark:hover:bg-white/15 disabled:opacity-40"
                      aria-label="Adjuntar imagen o PDF"
                    >
                      <Paperclip size={18} />
                    </button>
                    <textarea
                      value={draft}
                      onChange={(event) => setDraft(event.target.value)}
                      onKeyDown={handleComposerKeyDown}
                      rows={1}
                      placeholder="Escriba su mensaje…"
                      className="flex-1 resize-none rounded-xl border border-black/10 dark:border-white/10 bg-white dark:bg-zinc-800 px-3 py-2.5 text-sm outline-none focus-visible:ring-2 focus-visible:ring-cercano-blue/40 max-h-28"
                    />
                    <button
                      type="button"
                      onClick={handleSend}
                      disabled={!draft.trim() || sending}
                      className="btn-apple p-2.5 rounded-xl text-white disabled:opacity-40"
                      style={{ backgroundColor: branding.accent_color }}
                      aria-label="Enviar mensaje"
                    >
                      {sending ? (
                        <CheckCircle2 size={18} className="animate-pulse" />
                      ) : (
                        <Send size={18} />
                      )}
                    </button>
                  </div>
                )}
                <p className="mt-2 flex items-center justify-center gap-1.5 text-[11px] text-cercano-slate dark:text-gray-500">
                  <ShieldCheck size={12} />
                  {branding.privacy_text || DEFAULT_BRANDING.privacy_text}
                </p>
              </div>
            </>
          )}
        </AppleCard>
      </div>

      <ChatBrandingForm
        isOpen={brandingOpen}
        onClose={() => setBrandingOpen(false)}
        branding={branding}
        onSaved={setBranding}
      />
    </div>
  );
};
