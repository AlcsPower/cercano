// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React, { useEffect, useState } from 'react';
import { Palette, Save } from 'lucide-react';
import { chatApi } from '../../api/chat';
import { ChatBranding } from '../../types';
import { AppleButton } from '../common/AppleButton';
import { AppleSheet } from '../common/AppleSheet';

interface ChatBrandingFormProps {
  isOpen: boolean;
  onClose: () => void;
  branding: ChatBranding;
  onSaved: (branding: ChatBranding) => void;
}

const HEX_COLOR = /^#[0-9a-fA-F]{6}$/;
const HTTPS_URL = /^https:\/\/\S+$/i;

export const ChatBrandingForm: React.FC<ChatBrandingFormProps> = ({
  isOpen,
  onClose,
  branding,
  onSaved,
}) => {
  const [supportName, setSupportName] = useState(branding.support_name || 'Cercano Soporte');
  const [organizationName, setOrganizationName] = useState(branding.organization_name || '');
  const [logoUrl, setLogoUrl] = useState(branding.logo_url || '');
  const [accentColor, setAccentColor] = useState(branding.accent_color || '#3B5BFF');
  const [welcomeText, setWelcomeText] = useState(branding.welcome_text || '');
  const [infoText, setInfoText] = useState(branding.info_text || '');
  const [privacyText, setPrivacyText] = useState(branding.privacy_text || '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isOpen) return;
    setSupportName(branding.support_name || 'Cercano Soporte');
    setOrganizationName(branding.organization_name || '');
    setLogoUrl(branding.logo_url || '');
    setAccentColor(branding.accent_color || '#3B5BFF');
    setWelcomeText(branding.welcome_text || '');
    setInfoText(branding.info_text || '');
    setPrivacyText(branding.privacy_text || '');
    setError(null);
  }, [isOpen, branding]);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!supportName.trim()) {
      setError('El nombre de soporte es obligatorio.');
      return;
    }
    if (!HEX_COLOR.test(accentColor)) {
      setError('El color debe tener el formato #RRGGBB.');
      return;
    }
    if (logoUrl.trim() && !HTTPS_URL.test(logoUrl.trim())) {
      setError('El logo debe ser una URL https:// válida.');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const updated = await chatApi.updateBranding({
        support_name: supportName.trim(),
        organization_name: organizationName.trim() || null,
        logo_url: logoUrl.trim() || null,
        accent_color: accentColor,
        welcome_text: welcomeText.trim() || null,
        info_text: infoText.trim() || null,
        privacy_text: privacyText.trim() || null,
      });
      onSaved(updated);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'No se pudo guardar la marca.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <AppleSheet
      isOpen={isOpen}
      onClose={onClose}
      title="Marca del chat"
      subtitle="La marca de la ventana se configura aquí; el icono del instalador sigue en el perfil."
      maxWidth="max-w-2xl"
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="flex items-center gap-3 rounded-2xl bg-black/5 dark:bg-white/5 p-4">
          <div
            className="w-12 h-12 rounded-2xl flex items-center justify-center text-white shrink-0"
            style={{ backgroundColor: accentColor }}
            aria-hidden="true"
          >
            <Palette size={22} />
          </div>
          <div>
            <p className="text-sm font-semibold text-cercano-night dark:text-white">
              {supportName || 'Cercano Soporte'}
            </p>
            <p className="text-xs text-cercano-slate dark:text-gray-400">
              {organizationName || 'Organización sin nombre'}
            </p>
          </div>
        </div>

        {error && (
          <p role="alert" className="text-sm text-red-600 dark:text-red-400">
            {error}
          </p>
        )}

        <div className="grid sm:grid-cols-2 gap-4">
          <label className="block text-sm font-medium text-cercano-night dark:text-white">
            Nombre de soporte
            <input
              value={supportName}
              onChange={(event) => setSupportName(event.target.value)}
              maxLength={64}
              className="mt-1 w-full rounded-xl border border-black/10 dark:border-white/10 bg-white dark:bg-zinc-800 px-3 py-2 text-sm outline-none focus-visible:ring-2 focus-visible:ring-cercano-blue/40"
            />
          </label>
          <label className="block text-sm font-medium text-cercano-night dark:text-white">
            Organización
            <input
              value={organizationName}
              onChange={(event) => setOrganizationName(event.target.value)}
              maxLength={128}
              className="mt-1 w-full rounded-xl border border-black/10 dark:border-white/10 bg-white dark:bg-zinc-800 px-3 py-2 text-sm outline-none focus-visible:ring-2 focus-visible:ring-cercano-blue/40"
            />
          </label>
          <label className="block text-sm font-medium text-cercano-night dark:text-white">
            URL del logo (https)
            <input
              value={logoUrl}
              onChange={(event) => setLogoUrl(event.target.value)}
              placeholder="https://ejemplo.local/logo.png"
              className="mt-1 w-full rounded-xl border border-black/10 dark:border-white/10 bg-white dark:bg-zinc-800 px-3 py-2 text-sm outline-none focus-visible:ring-2 focus-visible:ring-cercano-blue/40"
            />
          </label>
          <label className="block text-sm font-medium text-cercano-night dark:text-white">
            Color de acento
            <span className="mt-1 flex items-center gap-2">
              <input
                type="color"
                value={accentColor}
                onChange={(event) => setAccentColor(event.target.value)}
                aria-label="Color de acento"
                className="h-10 w-12 rounded-lg border border-black/10 dark:border-white/10 bg-transparent"
              />
              <input
                value={accentColor}
                onChange={(event) => setAccentColor(event.target.value)}
                className="w-full rounded-xl border border-black/10 dark:border-white/10 bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-mono outline-none focus-visible:ring-2 focus-visible:ring-cercano-blue/40"
              />
            </span>
          </label>
        </div>

        <label className="block text-sm font-medium text-cercano-night dark:text-white">
          Texto de bienvenida
          <textarea
            value={welcomeText}
            onChange={(event) => setWelcomeText(event.target.value)}
            maxLength={512}
            rows={2}
            className="mt-1 w-full rounded-xl border border-black/10 dark:border-white/10 bg-white dark:bg-zinc-800 px-3 py-2 text-sm outline-none focus-visible:ring-2 focus-visible:ring-cercano-blue/40"
          />
        </label>
        <label className="block text-sm font-medium text-cercano-night dark:text-white">
          Aviso de la conversación
          <textarea
            value={infoText}
            onChange={(event) => setInfoText(event.target.value)}
            maxLength={512}
            rows={2}
            className="mt-1 w-full rounded-xl border border-black/10 dark:border-white/10 bg-white dark:bg-zinc-800 px-3 py-2 text-sm outline-none focus-visible:ring-2 focus-visible:ring-cercano-blue/40"
          />
        </label>
        <label className="block text-sm font-medium text-cercano-night dark:text-white">
          Texto de privacidad (pie)
          <textarea
            value={privacyText}
            onChange={(event) => setPrivacyText(event.target.value)}
            maxLength={512}
            rows={2}
            className="mt-1 w-full rounded-xl border border-black/10 dark:border-white/10 bg-white dark:bg-zinc-800 px-3 py-2 text-sm outline-none focus-visible:ring-2 focus-visible:ring-cercano-blue/40"
          />
        </label>

        <div className="flex justify-end gap-2 pt-2">
          <AppleButton type="button" variant="ghost" onClick={onClose}>
            Cancelar
          </AppleButton>
          <AppleButton type="submit" isLoading={saving} icon={<Save size={16} />}>
            Guardar marca
          </AppleButton>
        </div>
      </form>
    </AppleSheet>
  );
};
