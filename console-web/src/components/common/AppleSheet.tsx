// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React, { useEffect, useRef, useState, useId } from 'react';
import { createPortal } from 'react-dom';
import { X } from 'lucide-react';

interface AppleSheetProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  maxWidth?: string;
}

export const AppleSheet: React.FC<AppleSheetProps> = ({
  isOpen,
  onClose,
  title,
  subtitle,
  children,
  maxWidth = 'max-w-xl',
}) => {
  const [isRendered, setIsRendered] = useState(isOpen);
  const [isVisible, setIsVisible] = useState(false);
  const previousActiveElementRef = useRef<HTMLElement | null>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const generatedId = useId();
  const titleId = `sheet-title-${generatedId}`;

  const isClosing = isRendered && !isOpen;

  // Mount/unmount and visibility lifecycle with 200ms exit transition
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;
    let rafId: number;

    if (isOpen) {
      if (document.activeElement instanceof HTMLElement) {
        previousActiveElementRef.current = document.activeElement;
      }
      setIsRendered(true);
      rafId = requestAnimationFrame(() => {
        rafId = requestAnimationFrame(() => {
          setIsVisible(true);
        });
      });
    } else {
      setIsVisible(false);
      timer = setTimeout(() => {
        setIsRendered(false);
        if (
          previousActiveElementRef.current &&
          typeof previousActiveElementRef.current.focus === 'function'
        ) {
          previousActiveElementRef.current.focus();
          previousActiveElementRef.current = null;
        }
      }, 200);
    }

    return () => {
      cancelAnimationFrame(rafId);
      clearTimeout(timer);
    };
  }, [isOpen]);

  // Restore focus if unmounted prematurely
  useEffect(() => {
    return () => {
      if (
        previousActiveElementRef.current &&
        typeof previousActiveElementRef.current.focus === 'function'
      ) {
        previousActiveElementRef.current.focus();
      }
    };
  }, []);

  // Scroll lock with scrollbar width compensation
  useEffect(() => {
    if (!isRendered) return;

    const originalOverflow = document.body.style.overflow;
    const originalPaddingRight = document.body.style.paddingRight;
    const scrollbarWidth = window.innerWidth - document.documentElement.clientWidth;

    document.body.style.overflow = 'hidden';
    if (scrollbarWidth > 0) {
      document.body.style.paddingRight = `${scrollbarWidth}px`;
    }

    return () => {
      document.body.style.overflow = originalOverflow;
      document.body.style.paddingRight = originalPaddingRight;
    };
  }, [isRendered]);

  // Focus trap and keyboard handling
  useEffect(() => {
    if (!isRendered) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onClose();
        return;
      }

      if (e.key === 'Tab' && dialogRef.current) {
        const focusables = dialogRef.current.querySelectorAll<HTMLElement>(
          'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"]):not([disabled])'
        );
        const focusableArr = Array.from(focusables).filter(
          (el) => el.offsetParent !== null || el === document.activeElement
        );

        if (focusableArr.length === 0) {
          e.preventDefault();
          return;
        }

        const first = focusableArr[0];
        const last = focusableArr[focusableArr.length - 1];

        if (e.shiftKey) {
          if (document.activeElement === first || !dialogRef.current.contains(document.activeElement)) {
            e.preventDefault();
            last.focus();
          }
        } else {
          if (document.activeElement === last || !dialogRef.current.contains(document.activeElement)) {
            e.preventDefault();
            first.focus();
          }
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [isRendered, onClose]);

  // Focus close button or first interactive element when opened
  useEffect(() => {
    if (isVisible && isRendered) {
      const focusTimer = setTimeout(() => {
        if (closeButtonRef.current) {
          closeButtonRef.current.focus();
        } else if (dialogRef.current) {
          const firstFocusable = dialogRef.current.querySelector<HTMLElement>(
            'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"]):not([disabled])'
          );
          firstFocusable?.focus();
        }
      }, 50);

      return () => clearTimeout(focusTimer);
    }
  }, [isVisible, isRendered]);

  if (!isRendered || typeof document === 'undefined') return null;

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 overflow-y-auto"
      onClick={(e) => {
        if (e.target === e.currentTarget) {
          onClose();
        }
      }}
    >
      {/* Dimming Scrim with backdrop blur (active, interruptible transition) */}
      <div
        className={`fixed inset-0 bg-black/40 backdrop-blur-md transition-opacity ease-out ${
          isVisible ? 'opacity-100 duration-300' : 'opacity-0 duration-200'
        }`}
        onClick={onClose}
        aria-hidden="true"
        data-state={isVisible ? 'open' : 'closed'}
      />

      {/* Floating Apple Sheet / Card Modal with transform-origin: center */}
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        data-state={isVisible ? 'open' : 'closed'}
        style={{ transformOrigin: 'center' }}
        className={`relative w-full ${maxWidth} bg-white/90 dark:bg-zinc-900/90 backdrop-blur-2xl rounded-3xl p-6 sm:p-8 shadow-2xl border border-black/10 dark:border-white/[0.08] z-10 origin-center transition-[opacity,transform] ${
          isVisible
            ? 'opacity-100 translate-y-0 scale-100 duration-300 ease-[cubic-bezier(0.16,1,0.3,1)]'
            : isClosing
            ? 'opacity-0 translate-y-3 scale-[0.98] duration-200 ease-out'
            : 'opacity-0 translate-y-4 scale-[0.98] duration-300'
        }`}
      >
        {/* Sheet Grab Handle / Top pill */}
        <div className="flex justify-center -mt-2 mb-4">
          <div className="w-12 h-1.5 rounded-full bg-black/15 dark:bg-white/20" />
        </div>

        {/* Header */}
        <div className="flex items-start justify-between pb-4 mb-6 border-b border-black/5 dark:border-white/[0.04]">
          <div>
            <h2
              id={titleId}
              className="text-xl sm:text-2xl font-bold tracking-apple-title text-cercano-night dark:text-white"
            >
              {title}
            </h2>
            {subtitle && (
              <p className="text-sm text-cercano-slate dark:text-gray-400 mt-1">
                {subtitle}
              </p>
            )}
          </div>

          <button
            ref={closeButtonRef}
            onClick={onClose}
            className="btn-apple p-2 rounded-full bg-black/5 hover:bg-black/10 dark:bg-white/10 dark:hover:bg-white/15 text-cercano-slate dark:text-gray-300 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-cercano-blue"
            aria-label="Cerrar modal"
          >
            <X size={18} />
          </button>
        </div>

        {/* Content */}
        <div className="max-h-[75vh] overflow-y-auto pr-1">
          {children}
        </div>
      </div>
    </div>,
    document.body
  );
};
