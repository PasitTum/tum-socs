// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import React from 'react';
import { AlertCircle, CheckCircle2, Info, X } from 'lucide-react';

export interface NotificationState {
  isOpen: boolean;
  type: 'success' | 'error' | 'info';
  title: string;
  message: string;
}

interface CyberNotificationModalProps {
  notification: NotificationState;
  onClose: () => void;
}

export const CyberNotificationModal: React.FC<CyberNotificationModalProps> = ({
  notification,
  onClose,
}) => {
  if (!notification.isOpen) return null;

  const isError = notification.type === 'error';
  const isSuccess = notification.type === 'success';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 select-none">
      <div
        className={`bg-[#161b22] border rounded w-full max-w-md overflow-hidden font-sans relative ${
          isError
            ? 'border-[#f85149]/40'
            : isSuccess
            ? 'border-[#2ea043]/40'
            : 'border-[#30363d]'
        }`}
      >
        <div className="p-4">
          <div className="flex items-start justify-between mb-3">
            <div className="flex items-center gap-2.5">
              <div
                className={`w-7 h-7 rounded flex items-center justify-center ${
                  isError
                    ? 'bg-[#3c1e1e] text-[#f85149]'
                    : isSuccess
                    ? 'bg-[#132a1c] text-[#2ea043]'
                    : 'bg-[#21262d] text-[#58a6ff]'
                }`}
              >
                {isError ? (
                  <AlertCircle className="w-4 h-4" />
                ) : isSuccess ? (
                  <CheckCircle2 className="w-4 h-4" />
                ) : (
                  <Info className="w-4 h-4" />
                )}
              </div>
              <div>
                <h4 className="text-xs font-bold text-[#f0f6fc]">{notification.title}</h4>
                <span className="text-[9px] font-mono text-[#8b949e] uppercase tracking-wider">
                  SYSTEM NOTIFICATION
                </span>
              </div>
            </div>

            <button
              type="button"
              onClick={onClose}
              className="text-[#8b949e] hover:text-white p-1 rounded bg-[#21262d] border border-[#30363d] cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>

          <p className="text-xs text-[#c9d1d9] leading-relaxed font-sans mb-4">
            {notification.message}
          </p>

          <div className="flex justify-end">
            <button
              type="button"
              onClick={onClose}
              className={`px-3 py-1.5 rounded text-xs font-medium cursor-pointer transition-colors ${
                isError
                  ? 'bg-[#3c1e1e] hover:bg-[#4d2525] text-[#f85149] border border-[#f85149]/40'
                  : 'bg-[#1f6feb] hover:bg-[#388bfd] text-white'
              }`}
            >
              Dismiss
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
