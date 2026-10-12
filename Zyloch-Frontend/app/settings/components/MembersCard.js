"use client";

import React, { useCallback, useEffect, useState } from "react";
import { UserPlus, UserX, UserCheck, Users, Copy, Check, Clock, X, Trash2 } from "lucide-react";
import { toast } from "react-toastify";
import {
  deactivateMember,
  deleteMember,
  inviteMember,
  listMembers,
  reactivateMember,
  revokeInvite,
} from "@/lib/api/organization";
import { useTenant } from "@/context/TenantContext";
import Modal from "@/components/common/Modal";

export function MembersCard({ isAdmin: isAdminProp } = {}) {
  const { isAdmin: tenantIsAdmin, tenantId } = useTenant();
  // Prefer the caller's (page-level) admin state, which already unions the
  // direct org fetch with TenantContext — falling back to context alone keeps
  // this component usable standalone. See settings/page.js for the union logic.
  const isAdmin = isAdminProp ?? tenantIsAdmin;
  const [members, setMembers] = useState([]);
  const [pendingInvites, setPendingInvites] = useState([]);
  const [usage, setUsage] = useState(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [revokingId, setRevokingId] = useState(null);

  const [isInviteOpen, setIsInviteOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [inviteUrl, setInviteUrl] = useState("");
  const [copied, setCopied] = useState(false);

  const [memberToDelete, setMemberToDelete] = useState(null);
  const [deleting, setDeleting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await listMembers(false);
      setMembers(data.members || []);
      setPendingInvites(data.pendingInvites || []);
      setUsage(data.usage || null);
    } catch {
      setMembers([]);
      setPendingInvites([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (tenantId) load();
  }, [tenantId, load]);

  const openInviteModal = () => {
    setEmail("");
    setInviteUrl("");
    setCopied(false);
    setIsInviteOpen(true);
  };

  const closeInviteModal = () => {
    setIsInviteOpen(false);
  };

  const onInvite = async (e) => {
    e.preventDefault();
    if (!email.trim()) return;
    setBusy(true);
    try {
      const res = await inviteMember(email.trim(), true);
      setInviteUrl(res.invite?.inviteUrl || "");
      toast.success(`Invite sent to ${email.trim()}`);
      setEmail("");
      await load();
    } catch {
      /* toast from API helper */
    } finally {
      setBusy(false);
    }
  };

  const copyInviteLink = async () => {
    if (!inviteUrl) return;
    try {
      await navigator.clipboard.writeText(inviteUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      console.error("Failed to copy invite link:", error);
    }
  };

  const onDeactivate = async (id) => {
    setBusy(true);
    try {
      await deactivateMember(id, true);
      await load();
    } finally {
      setBusy(false);
    }
  };

  const onReactivate = async (id) => {
    setBusy(true);
    try {
      await reactivateMember(id, true);
      await load();
    } finally {
      setBusy(false);
    }
  };

  const openDeleteConfirm = (member) => setMemberToDelete(member);
  const closeDeleteConfirm = () => {
    if (deleting) return;
    setMemberToDelete(null);
  };

  const onConfirmDelete = async () => {
    if (!memberToDelete) return;
    setDeleting(true);
    try {
      await deleteMember(memberToDelete.id, true);
      setMemberToDelete(null);
      await load();
    } finally {
      setDeleting(false);
    }
  };

  const onRevokeInvite = async (id) => {
    setRevokingId(id);
    try {
      await revokeInvite(id, true);
      await load();
    } finally {
      setRevokingId(null);
    }
  };

  return (
    <div className="rounded-xl p-5" style={{ border: "1px solid var(--border)", background: "var(--surface)" }}>
      <div className="flex items-center gap-2 mb-4">
        <Users size={18} />
        <h3 className="text-base font-semibold m-0">Members</h3>
        {usage?.users && (
          <span className="text-xs ml-2" style={{ color: "var(--muted)" }}>
            {usage.users.current}/{usage.users.max} seats
          </span>
        )}
        {isAdmin && (
          <button
            type="button"
            onClick={openInviteModal}
            className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium ml-auto"
            style={{ background: "var(--color-primary)", color: "var(--text-on-primary)" }}
          >
            <UserPlus size={14} /> Invite
          </button>
        )}
      </div>

      {!isAdmin && (
        <p className="text-xs mb-3" style={{ color: "var(--muted)" }}>
          Members can view the roster; only admins can invite, deactivate, or delete.
        </p>
      )}

      {loading ? (
        <p className="text-sm" style={{ color: "var(--muted)" }}>
          Loading members…
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ color: "var(--muted)", textAlign: "left" }}>
                <th className="py-2">Name</th>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                {isAdmin && <th>Actions</th>}
              </tr>
            </thead>
            <tbody>
              {members.map((m) => (
                <tr key={m.id} style={{ borderTop: "1px solid var(--border)" }}>
                  <td className="py-2">{m.name || "—"}</td>
                  <td>{m.email}</td>
                  <td>{m.role}</td>
                  <td>{m.isActive ? "active" : "deactivated"}</td>
                  {isAdmin && (
                    <td>
                      {m.role !== "admin" && (
                        <div className="flex items-center gap-2">
                          {m.isActive ? (
                            <button
                              type="button"
                              title="Deactivate member"
                              aria-label="Deactivate member"
                              disabled={busy}
                              onClick={() => onDeactivate(m.id)}
                              className="inline-flex items-center p-1 rounded-md"
                              style={{ color: "#b91c1c" }}
                            >
                              <UserX size={14} />
                            </button>
                          ) : (
                            <button
                              type="button"
                              title="Reactivate member"
                              aria-label="Reactivate member"
                              disabled={busy}
                              onClick={() => onReactivate(m.id)}
                              className="inline-flex items-center p-1 rounded-md"
                              style={{ color: "var(--color-primary)" }}
                            >
                              <UserCheck size={14} />
                            </button>
                          )}
                          <button
                            type="button"
                            title="Delete member"
                            aria-label="Delete member"
                            disabled={busy}
                            onClick={() => openDeleteConfirm(m)}
                            className="inline-flex items-center p-1 rounded-md"
                            style={{ color: "#b91c1c" }}
                          >
                            <Trash2 size={14} />
                          </button>
                        </div>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {!loading && pendingInvites.length > 0 && (
        <div className="mt-5">
          <div className="flex items-center gap-2 mb-2">
            <Clock size={14} style={{ color: "var(--muted)" }} />
            <h4 className="text-sm font-medium m-0" style={{ color: "var(--text)" }}>
              Pending invitations
            </h4>
            <span className="text-xs" style={{ color: "var(--muted)" }}>
              ({pendingInvites.length})
            </span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ color: "var(--muted)", textAlign: "left" }}>
                  <th className="py-2">Email</th>
                  <th>Invited</th>
                  <th>Expires</th>
                  {isAdmin && <th>Actions</th>}
                </tr>
              </thead>
              <tbody>
                {pendingInvites.map((invite) => (
                  <tr key={invite.id} style={{ borderTop: "1px solid var(--border)" }}>
                    <td className="py-2">{invite.email}</td>
                    <td>
                      {invite.invitedAt
                        ? new Date(invite.invitedAt).toLocaleDateString()
                        : "—"}
                    </td>
                    <td>
                      {invite.expiresAt
                        ? new Date(invite.expiresAt).toLocaleDateString()
                        : "—"}
                    </td>
                    {isAdmin && (
                      <td>
                        <button
                          type="button"
                          disabled={revokingId === invite.id}
                          onClick={() => onRevokeInvite(invite.id)}
                          className="inline-flex items-center gap-1 text-xs"
                          style={{ color: "#b91c1c" }}
                        >
                          <X size={12} /> Revoke
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <Modal isOpen={isInviteOpen} onClose={closeInviteModal} title="Invite a member" size="sm">
        <form onSubmit={onInvite} className="flex flex-col gap-3">
          <label className="text-sm font-medium" style={{ color: "var(--text)" }}>
            Email address
          </label>
          <input
            type="email"
            required
            autoFocus
            placeholder="member@company.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="rounded-lg px-3 py-2 text-sm"
            style={{ border: "1px solid var(--border)", background: "var(--bg)" }}
          />
          <button
            type="submit"
            disabled={busy}
            className="inline-flex items-center justify-center gap-1.5 rounded-lg px-3 py-2 text-sm font-medium"
            style={{ background: "var(--color-primary)", color: "var(--text-on-primary)" }}
          >
            <UserPlus size={14} /> {inviteUrl ? "Send another invite" : "Send invite"}
          </button>
        </form>

        {inviteUrl && (
          <div className="mt-4">
            <p className="text-xs font-medium mb-2" style={{ color: "var(--muted)" }}>
              Share this invite link:
            </p>
            <div
              className="flex items-center gap-2 p-3 rounded-lg"
              style={{ background: "var(--elevated-surface)", border: "1px solid var(--border)" }}
            >
              <code className="text-xs font-mono break-all flex-1 min-w-0" style={{ color: "var(--text)" }}>
                {inviteUrl}
              </code>
              <button
                type="button"
                onClick={copyInviteLink}
                disabled={copied}
                title="Copy invite link"
                className="p-1.5 rounded-md shrink-0"
                style={{ background: "var(--surface)" }}
              >
                {copied ? (
                  <Check size={16} style={{ color: "var(--success)" }} />
                ) : (
                  <Copy size={16} style={{ color: "var(--muted)" }} />
                )}
              </button>
            </div>
          </div>
        )}
      </Modal>

      <Modal
        isOpen={!!memberToDelete}
        onClose={closeDeleteConfirm}
        title="Delete member"
        size="sm"
      >
        <p className="text-sm mb-4" style={{ color: "var(--text)" }}>
          This will permanently remove{" "}
          <strong>{memberToDelete?.name || memberToDelete?.email}</strong> from the
          organization. This action cannot be undone.
        </p>
        <div className="flex items-center justify-end gap-2">
          <button
            type="button"
            disabled={deleting}
            onClick={closeDeleteConfirm}
            className="rounded-lg px-3 py-1.5 text-sm font-medium"
            style={{ border: "1px solid var(--border)", color: "var(--text)" }}
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={deleting}
            onClick={onConfirmDelete}
            className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium"
            style={{ background: "#b91c1c", color: "#fff" }}
          >
            <Trash2 size={14} /> {deleting ? "Deleting…" : "Delete"}
          </button>
        </div>
      </Modal>
    </div>
  );
}
