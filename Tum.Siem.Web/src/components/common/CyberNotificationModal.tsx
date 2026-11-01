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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md select-none animate-fadeIn">
      <div
        className={`bg-[#080d1a] border rounded-3xl w-full max-w-md shadow-2xl overflow-hidden font-sans relative ${
          isError
            ? 'border-rose-500/50 shadow-[0_0_40px_rgba(244,63,94,0.3)]'
            : isSuccess
            ? 'border-emerald-500/50 shadow-[0_0_40px_rgba(16,185,129,0.3)]'
            : 'border-cyan-500/50 shadow-[0_0_40px_rgba(56,189,248,0.3)]'
        }`}
      >
        <div className="p-6">
          <div className="flex items-start justify-between mb-4">
            <div className="flex items-center gap-3">
              <div
                className={`w-10 h-10 rounded-2xl flex items-center justify-center ${
                  isError
                    ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                    : isSuccess
                    ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                    : 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30'
                }`}
              >
                {isError ? (
                  <AlertCircle className="w-5 h-5" />
                ) : isSuccess ? (
                  <CheckCircle2 className="w-5 h-5" />
                ) : (
                  <Info className="w-5 h-5" />
                )}
              </div>
              <div>
                <h4 className="text-base font-black text-white">{notification.title}</h4>
                <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">
                  SYSTEM NOTIFICATION
                </span>
              </div>
            </div>

            <button
              type="button"
              onClick={onClose}
              className="text-slate-400 hover:text-white p-1.5 rounded-xl bg-slate-900 border border-white/10 cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <p className="text-xs text-slate-300 font-mono leading-relaxed bg-[#0b1224] p-3.5 rounded-2xl border border-white/5">
            {notification.message}
          </p>

          <div className="mt-5 flex justify-end">
            <button
              type="button"
              onClick={onClose}
              className={`px-5 py-2 rounded-xl text-xs font-bold cursor-pointer transition-all active:scale-95 ${
                isError
                  ? 'bg-rose-500 hover:bg-rose-400 text-white shadow-[0_0_15px_rgba(244,63,94,0.3)]'
                  : isSuccess
                  ? 'bg-emerald-500 hover:bg-emerald-400 text-slate-950 shadow-[0_0_15px_rgba(16,185,129,0.3)]'
                  : 'bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-[0_0_15px_rgba(56,189,248,0.3)]'
              }`}
            >
              OK / ตกลง
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
