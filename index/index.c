/**
 * @file
 * GUI manage the main index (list of emails)
 *
 * @authors
 * Copyright (C) 1996-2000,2002,2010,2012-2013 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2020 R Primus <rprimus@gmail.com>
 *
 * @copyright
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @page index_index GUI manage the main index (list of emails)
 *
 * GUI manage the main index (list of emails)
 */

#include "config.h"
#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "email/lib.h"
#include "core/lib.h"
#include "alias/lib.h"
#include "conn/lib.h"
#include "gui/lib.h"
#include "mutt.h"
#include "debug/lib.h"
#include "lib.h"
#include "ncrypt/lib.h"
#include "pattern/lib.h"
#include "send/lib.h"
#include "browser.h"
#include "commands.h"
#include "context.h"
#include "format_flags.h"
#include "functions.h"
#include "hdrline.h"
#include "hook.h"
#include "index_data.h"
#include "keymap.h"
#include "mutt_globals.h"
#include "mutt_header.h"
#include "mutt_logging.h"
#include "mutt_mailbox.h"
#include "mutt_menu.h"
#include "mutt_thread.h"
#include "muttlib.h"
#include "mx.h"
#include "opcodes.h"
#include "options.h"
#include "pager.h"
#include "progress.h"
#include "protos.h"
#include "recvattach.h"
#include "score.h"
#include "sort.h"
#include "status.h"
#ifdef USE_SIDEBAR
#include "sidebar/lib.h"
#endif
#ifdef USE_POP
#include "pop/lib.h"
#endif
#ifdef USE_IMAP
#include "imap/lib.h"
#endif
#ifdef USE_NOTMUCH
#include "notmuch/lib.h"
#endif
#ifdef USE_NNTP
#include "nntp/lib.h"
#include "nntp/adata.h"
#include "nntp/mdata.h"
#endif
#ifdef ENABLE_NLS
#include <libintl.h>
#endif
#ifdef USE_INOTIFY
#include "monitor.h"
#endif
#ifdef USE_AUTOCRYPT
#include "autocrypt/lib.h"
#endif

/// Help Bar for the Index dialog
static const struct Mapping IndexHelp[] = {
  // clang-format off
  { N_("Quit"),  OP_QUIT },
  { N_("Del"),   OP_DELETE },
  { N_("Undel"), OP_UNDELETE },
  { N_("Save"),  OP_SAVE },
  { N_("Mail"),  OP_MAIL },
  { N_("Reply"), OP_REPLY },
  { N_("Group"), OP_GROUP_REPLY },
  { N_("Help"),  OP_HELP },
  { NULL, 0 },
  // clang-format on
};

#ifdef USE_NNTP
/// Help Bar for the News Index dialog
const struct Mapping IndexNewsHelp[] = {
  // clang-format off
  { N_("Quit"),     OP_QUIT },
  { N_("Del"),      OP_DELETE },
  { N_("Undel"),    OP_UNDELETE },
  { N_("Save"),     OP_SAVE },
  { N_("Post"),     OP_POST },
  { N_("Followup"), OP_FOLLOWUP },
  { N_("Catchup"),  OP_CATCHUP },
  { N_("Help"),     OP_HELP },
  { NULL, 0 },
  // clang-format on
};
#endif

/**
 * prereq - Check the pre-requisites for a function
 * @param ctx    Mailbox
 * @param menu   Current Menu
 * @param checks Checks to perform, see #CheckFlags
 * @retval bool true if the checks pass successfully
 */
bool prereq(struct Context *ctx, struct Menu *menu, CheckFlags checks)
{
  bool result = true;

  if (checks & (CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY))
    checks |= CHECK_IN_MAILBOX;

  if ((checks & CHECK_IN_MAILBOX) && (!ctx || !ctx->mailbox))
  {
    mutt_error(_("No mailbox is open"));
    result = false;
  }

  if (result && (checks & CHECK_MSGCOUNT) && (ctx->mailbox->msg_count == 0))
  {
    mutt_error(_("There are no messages"));
    result = false;
  }

  if (result && (checks & CHECK_VISIBLE) && (menu->current >= ctx->mailbox->vcount))
  {
    mutt_error(_("No visible messages"));
    result = false;
  }

  if (result && (checks & CHECK_READONLY) && ctx->mailbox->readonly)
  {
    mutt_error(_("Mailbox is read-only"));
    result = false;
  }

  if (result && (checks & CHECK_ATTACH) && OptAttachMsg)
  {
    mutt_error(_("Function not permitted in attach-message mode"));
    result = false;
  }

  if (!result)
    mutt_flushinp();

  return result;
}

/**
 * check_acl - Check the ACLs for a function
 * @param m   Mailbox
 * @param acl ACL, see #AclFlags
 * @param msg Error message for failure
 * @retval bool true if the function is permitted
 */
bool check_acl(struct Mailbox *m, AclFlags acl, const char *msg)
{
  if (!m)
    return false;

  if (!(m->rights & acl))
  {
    /* L10N: %s is one of the CHECK_ACL entries below. */
    mutt_error(_("%s: Operation not permitted by ACL"), msg);
    return false;
  }

  return true;
}

/**
 * collapse_all - Collapse/uncollapse all threads
 * @param ctx    Context
 * @param menu   current menu
 * @param toggle toggle collapsed state
 *
 * This function is called by the OP_MAIN_COLLAPSE_ALL command and on folder
 * enter if the `$collapse_all` option is set. In the first case, the @a toggle
 * parameter is 1 to actually toggle collapsed/uncollapsed state on all
 * threads. In the second case, the @a toggle parameter is 0, actually turning
 * this function into a one-way collapse.
 */
void collapse_all(struct Context *ctx, struct Menu *menu, int toggle)
{
  if (!ctx || !ctx->mailbox || (ctx->mailbox->msg_count == 0) || !menu)
    return;

  struct Email *e_cur = mutt_get_virt_email(ctx->mailbox, menu->current);
  if (!e_cur)
    return;

  int final;

  /* Figure out what the current message would be after folding / unfolding,
   * so that we can restore the cursor in a sane way afterwards. */
  if (e_cur->collapsed && toggle)
    final = mutt_uncollapse_thread(e_cur);
  else if (mutt_thread_can_collapse(e_cur))
    final = mutt_collapse_thread(e_cur);
  else
    final = e_cur->vnum;

  if (final == -1)
    return;

  struct Email *base = mutt_get_virt_email(ctx->mailbox, final);
  if (!base)
    return;

  /* Iterate all threads, perform collapse/uncollapse as needed */
  ctx->collapsed = toggle ? !ctx->collapsed : true;
  mutt_thread_collapse(ctx->threads, ctx->collapsed);

  /* Restore the cursor */
  mutt_set_vnum(ctx->mailbox);
  for (int i = 0; i < ctx->mailbox->vcount; i++)
  {
    struct Email *e = mutt_get_virt_email(ctx->mailbox, i);
    if (!e)
      break;
    if (e->index == base->index)
    {
      menu->current = i;
      break;
    }
  }

  menu->redraw = REDRAW_INDEX | REDRAW_STATUS;
}

/**
 * ci_next_undeleted - Find the next undeleted email
 * @param m     Mailbox
 * @param msgno Message number to start at
 * @retval >=0 Message number of next undeleted email
 * @retval  -1 No more undeleted messages
 */
int ci_next_undeleted(struct Mailbox *m, int msgno)
{
  if (!m)
    return -1;

  for (int i = msgno + 1; i < m->vcount; i++)
  {
    struct Email *e = mutt_get_virt_email(m, i);
    if (!e)
      continue;
    if (!e->deleted)
      return i;
  }
  return -1;
}

/**
 * ci_previous_undeleted - Find the previous undeleted email
 * @param m     Mailbox
 * @param msgno Message number to start at
 * @retval >=0 Message number of next undeleted email
 * @retval  -1 No more undeleted messages
 */
int ci_previous_undeleted(struct Mailbox *m, int msgno)
{
  if (!m)
    return -1;

  for (int i = msgno - 1; i >= 0; i--)
  {
    struct Email *e = mutt_get_virt_email(m, i);
    if (!e)
      continue;
    if (!e->deleted)
      return i;
  }
  return -1;
}

/**
 * ci_first_message - Get index of first new message
 * @param m Mailbox
 * @retval num Index of first new message
 *
 * Return the index of the first new message, or failing that, the first
 * unread message.
 */
int ci_first_message(struct Mailbox *m)
{
  if (!m || (m->msg_count == 0))
    return 0;

  int old = -1;
  for (int i = 0; i < m->vcount; i++)
  {
    struct Email *e = mutt_get_virt_email(m, i);
    if (!e)
      continue;
    if (!e->read && !e->deleted)
    {
      if (!e->old)
        return i;
      if (old == -1)
        old = i;
    }
  }
  if (old != -1)
    return old;

  /* If `$sort` is reverse and not threaded, the latest message is first.
   * If `$sort` is threaded, the latest message is first if exactly one
   * of `$sort` and `$sort_aux` are reverse.  */
  const short c_sort = cs_subset_sort(NeoMutt->sub, "sort");
  const short c_sort_aux = cs_subset_sort(NeoMutt->sub, "sort_aux");
  if (((c_sort & SORT_REVERSE) && ((c_sort & SORT_MASK) != SORT_THREADS)) ||
      (((c_sort & SORT_MASK) == SORT_THREADS) && ((c_sort ^ c_sort_aux) & SORT_REVERSE)))
  {
    return 0;
  }
  else
  {
    return m->vcount ? m->vcount - 1 : 0;
  }

  return 0;
}

/**
 * mx_toggle_write - Toggle the mailbox's readonly flag
 * @param m Mailbox
 * @retval  0 Success
 * @retval -1 Error
 *
 * This should be in mx.c, but it only gets used here.
 */
int mx_toggle_write(struct Mailbox *m)
{
  if (!m)
    return -1;

  if (m->readonly)
  {
    mutt_error(_("Can't toggle write on a readonly mailbox"));
    return -1;
  }

  if (m->dontwrite)
  {
    m->dontwrite = false;
    mutt_message(_("Changes to folder will be written on folder exit"));
  }
  else
  {
    m->dontwrite = true;
    mutt_message(_("Changes to folder will not be written"));
  }

  return 0;
}

/**
 * resort_index - Resort the index
 * @param ctx  Context
 * @param menu Current Menu
 */
void resort_index(struct Context *ctx, struct Menu *menu)
{
  if (!ctx || !ctx->mailbox || !menu)
    return;

  struct Email *e_cur = mutt_get_virt_email(ctx->mailbox, menu->current);

  menu->current = -1;
  mutt_sort_headers(ctx->mailbox, ctx->threads, false, &ctx->vsize);
  /* Restore the current message */

  for (int i = 0; i < ctx->mailbox->vcount; i++)
  {
    struct Email *e = mutt_get_virt_email(ctx->mailbox, i);
    if (!e)
      continue;
    if (e == e_cur)
    {
      menu->current = i;
      break;
    }
  }

  const short c_sort = cs_subset_sort(NeoMutt->sub, "sort");
  if (((c_sort & SORT_MASK) == SORT_THREADS) && (menu->current < 0))
    menu->current = mutt_parent_message(e_cur, false);

  if (menu->current < 0)
    menu->current = ci_first_message(ctx->mailbox);

  menu->redraw |= REDRAW_INDEX | REDRAW_STATUS;
}

/**
 * update_index_threaded - Update the index (if threaded)
 * @param ctx      Mailbox
 * @param check    Flags, e.g. #MX_STATUS_REOPENED
 * @param oldcount How many items are currently in the index
 */
static void update_index_threaded(struct Context *ctx, enum MxStatus check, int oldcount)
{
  struct Email **save_new = NULL;
  const bool lmt = ctx_has_limit(ctx);

  int num_new = MAX(0, ctx->mailbox->msg_count - oldcount);

  const bool c_uncollapse_new = cs_subset_bool(NeoMutt->sub, "uncollapse_new");
  /* save the list of new messages */
  if ((check != MX_STATUS_REOPENED) && (oldcount > 0) &&
      (lmt || c_uncollapse_new) && (num_new > 0))
  {
    save_new = mutt_mem_malloc(num_new * sizeof(struct Email *));
    for (int i = oldcount; i < ctx->mailbox->msg_count; i++)
      save_new[i - oldcount] = ctx->mailbox->emails[i];
  }

  /* Sort first to thread the new messages, because some patterns
   * require the threading information.
   *
   * If the mailbox was reopened, need to rethread from scratch. */
  mutt_sort_headers(ctx->mailbox, ctx->threads, (check == MX_STATUS_REOPENED), &ctx->vsize);

  if (lmt)
  {
    /* Because threading changes the order in ctx->mailbox->emails, we don't
     * know which emails are new. Hence, we need to re-apply the limit to the
     * whole set.
     */
    for (int i = 0; i < ctx->mailbox->msg_count; i++)
    {
      struct Email *e = ctx->mailbox->emails[i];
      if ((e->vnum != -1) || mutt_pattern_exec(SLIST_FIRST(ctx->limit_pattern), MUTT_MATCH_FULL_ADDRESS,
                                               ctx->mailbox, e, NULL))
      {
        /* vnum will get properly set by mutt_set_vnum(), which
         * is called by mutt_sort_headers() just below. */
        e->vnum = 1;
        e->visible = true;
      }
      else
      {
        e->vnum = -1;
        e->visible = false;
      }
    }
    /* Need a second sort to set virtual numbers and redraw the tree */
    mutt_sort_headers(ctx->mailbox, ctx->threads, false, &ctx->vsize);
  }

  /* uncollapse threads with new mail */
  if (c_uncollapse_new)
  {
    if (check == MX_STATUS_REOPENED)
    {
      ctx->collapsed = false;
      mutt_thread_collapse(ctx->threads, ctx->collapsed);
      mutt_set_vnum(ctx->mailbox);
    }
    else if (oldcount > 0)
    {
      for (int j = 0; j < num_new; j++)
      {
        if (save_new[j]->visible)
        {
          mutt_uncollapse_thread(save_new[j]);
        }
      }
      mutt_set_vnum(ctx->mailbox);
    }
  }

  FREE(&save_new);
}

/**
 * update_index_unthreaded - Update the index (if unthreaded)
 * @param ctx      Mailbox
 * @param check    Flags, e.g. #MX_STATUS_REOPENED
 */
static void update_index_unthreaded(struct Context *ctx, enum MxStatus check)
{
  /* We are in a limited view. Check if the new message(s) satisfy
   * the limit criteria. If they do, set their virtual msgno so that
   * they will be visible in the limited view */
  if (ctx_has_limit(ctx))
  {
    int padding = mx_msg_padding_size(ctx->mailbox);
    ctx->mailbox->vcount = ctx->vsize = 0;
    for (int i = 0; i < ctx->mailbox->msg_count; i++)
    {
      struct Email *e = ctx->mailbox->emails[i];
      if (!e)
        break;
      if (mutt_pattern_exec(SLIST_FIRST(ctx->limit_pattern),
                            MUTT_MATCH_FULL_ADDRESS, ctx->mailbox, e, NULL))
      {
        assert(ctx->mailbox->vcount < ctx->mailbox->msg_count);
        e->vnum = ctx->mailbox->vcount;
        ctx->mailbox->v2r[ctx->mailbox->vcount] = i;
        e->visible = true;
        ctx->mailbox->vcount++;
        struct Body *b = e->body;
        ctx->vsize += b->length + b->offset - b->hdr_offset + padding;
      }
      else
      {
        e->visible = false;
      }
    }
  }

  /* if the mailbox was reopened, need to rethread from scratch */
  mutt_sort_headers(ctx->mailbox, ctx->threads, (check == MX_STATUS_REOPENED), &ctx->vsize);
}

/**
 * is_current_email - Check whether an email is the currently selected Email
 * @param cur  Currently selected Email
 * @param e    Email to check
 * @retval true e is current
 * @retval false e is not current
 */
static bool is_current_email(const struct CurrentEmail *cur, const struct Email *e)
{
  return cur->sequence == e->sequence;
}

/**
 * set_current_email - Keep track of the currently selected Email
 * @param cur Currently selected Email
 * @param e   Email to set as current
 */
void set_current_email(struct CurrentEmail *cur, struct Email *e)
{
  cur->e = e;
  cur->sequence = e ? e->sequence : 0;
}

/**
 * update_index - Update the index
 * @param menu       Current Menu
 * @param ctx        Mailbox
 * @param check      Flags, e.g. #MX_STATUS_REOPENED
 * @param oldcount   How many items are currently in the index
 * @param cur        Remember our place in the index
 */
void update_index(struct Menu *menu, struct Context *ctx, enum MxStatus check,
                  int oldcount, const struct CurrentEmail *cur)
{
  if (!menu || !ctx)
    return;

  const short c_sort = cs_subset_sort(NeoMutt->sub, "sort");
  if ((c_sort & SORT_MASK) == SORT_THREADS)
    update_index_threaded(ctx, check, oldcount);
  else
    update_index_unthreaded(ctx, check);

  const int old_current = menu->current;
  menu->current = -1;
  if (oldcount)
  {
    /* restore the current message to the message it was pointing to */
    for (int i = 0; i < ctx->mailbox->vcount; i++)
    {
      struct Email *e = mutt_get_virt_email(ctx->mailbox, i);
      if (!e)
        continue;
      if (is_current_email(cur, e))
      {
        menu->current = i;
        break;
      }
    }
  }

  if (menu->current < 0)
  {
    menu->current = (old_current < ctx->mailbox->vcount) ?
                        old_current :
                        ci_first_message(ctx->mailbox);
  }
}

/**
 * mutt_update_index - Update the index
 * @param menu      Current Menu
 * @param ctx       Mailbox
 * @param check     Flags, e.g. #MX_STATUS_REOPENED
 * @param oldcount  How many items are currently in the index
 * @param cur_email Currently selected email
 *
 * @note cur_email cannot be NULL
 */
void mutt_update_index(struct Menu *menu, struct Context *ctx, enum MxStatus check,
                       int oldcount, const struct Email *cur_email)
{
  struct CurrentEmail se = { .e = NULL, .sequence = cur_email->sequence };
  update_index(menu, ctx, check, oldcount, &se);
}

/**
 * mailbox_index_observer - Listen for Mailbox changes - Implements ::observer_t
 *
 * If a Mailbox is closed, then set a pointer to NULL.
 */
static int mailbox_index_observer(struct NotifyCallback *nc)
{
  if (!nc->global_data)
    return -1;
  if ((nc->event_type != NT_MAILBOX) || (nc->event_subtype != NT_MAILBOX_CLOSED))
    return 0;

  struct Mailbox **ptr = nc->global_data;
  if (!ptr || !*ptr)
    return 0;

  *ptr = NULL;
  return 0;
}

/**
 * change_folder_mailbox - Change to a different Mailbox by pointer
 * @param menu      Current Menu
 * @param m         Mailbox
 * @param oldcount  How many items are currently in the index
 * @param cur       Remember our place in the index
 * @param read_only Open Mailbox in read-only mode
 */
void change_folder_mailbox(struct Menu *menu, struct Mailbox *m, int *oldcount,
                           const struct CurrentEmail *cur, bool read_only)
{
  if (!m)
    return;

  struct Mailbox *m_ctx = ctx_mailbox(Contex2);
  /* keepalive failure in mutt_enter_fname may kill connection. */
  if (m_ctx && (mutt_buffer_is_empty(&m_ctx->pathbuf)))
    ctx_free(&Contex2);

  if (m_ctx)
  {
    char *new_last_folder = NULL;
#ifdef USE_INOTIFY
    int monitor_remove_rc = mutt_monitor_remove(NULL);
#endif
#ifdef USE_COMP_MBOX
    if (m_ctx->compress_info && (m_ctx->realpath[0] != '\0'))
      new_last_folder = mutt_str_dup(m_ctx->realpath);
    else
#endif
      new_last_folder = mutt_str_dup(mailbox_path(m_ctx));
    *oldcount = m_ctx->msg_count;

    const enum MxStatus check = mx_mbox_close(&Contex2);
    if (check != MX_STATUS_OK)
    {
#ifdef USE_INOTIFY
      if (monitor_remove_rc == 0)
        mutt_monitor_add(NULL);
#endif
      if ((check == MX_STATUS_NEW_MAIL) || (check == MX_STATUS_REOPENED))
        update_index(menu, Contex2, check, *oldcount, cur);

      FREE(&new_last_folder);
      OptSearchInvalid = true;
      menu->redraw |= REDRAW_INDEX | REDRAW_STATUS;
      return;
    }
    FREE(&LastFolder);
    LastFolder = new_last_folder;
  }
  mutt_str_replace(&CurrentFolder, mailbox_path(m));

  /* If the `folder-hook` were to call `unmailboxes`, then the Mailbox (`m`)
   * could be deleted, leaving `m` dangling. */
  // TODO: Refactor this function to avoid the need for an observer
  notify_observer_add(m->notify, NT_MAILBOX, mailbox_index_observer, &m);
  char *dup_path = mutt_str_dup(mailbox_path(m));
  char *dup_name = mutt_str_dup(m->name);

  mutt_folder_hook(dup_path, dup_name);
  if (m)
  {
    /* `m` is still valid, but we won't need the observer again before the end
     * of the function. */
    notify_observer_remove(m->notify, mailbox_index_observer, &m);
  }

  // Recreate the Mailbox as the folder-hook might have invoked `mailboxes`
  // and/or `unmailboxes`.
  m = mx_path_resolve(dup_path);
  FREE(&dup_path);
  FREE(&dup_name);

  if (!m)
    return;

  const OpenMailboxFlags flags = read_only ? MUTT_READONLY : MUTT_OPEN_NO_FLAGS;
  Contex2 = mx_mbox_open(m, flags);
  if (Contex2)
  {
    menu->current = ci_first_message(Contex2->mailbox);
#ifdef USE_INOTIFY
    mutt_monitor_add(NULL);
#endif
  }
  else
  {
    menu->current = 0;
  }

  const short c_sort = cs_subset_sort(NeoMutt->sub, "sort");
  const bool c_collapse_all = cs_subset_bool(NeoMutt->sub, "collapse_all");
  if (((c_sort & SORT_MASK) == SORT_THREADS) && c_collapse_all)
    collapse_all(Contex2, menu, 0);

  struct MuttWindow *dlg = dialog_find(menu->win_index);
  struct EventMailbox em = { Contex2 ? Contex2->mailbox : NULL };
  notify_send(dlg->notify, NT_MAILBOX, NT_MAILBOX_SWITCH, &em);

  mutt_clear_error();
  /* force the mailbox check after we have changed the folder */
  mutt_mailbox_check(em.mailbox, MUTT_MAILBOX_CHECK_FORCE);
  menu->redraw = REDRAW_FULL;
  OptSearchInvalid = true;
}

#ifdef USE_NOTMUCH
/**
 * change_folder_notmuch - Change to a different Notmuch Mailbox by string
 * @param menu      Current Menu
 * @param buf       Folder to change to
 * @param buflen    Length of buffer
 * @param oldcount  How many items are currently in the index
 * @param cur       Remember our place in the index
 * @param read_only Open Mailbox in read-only mode
 */
struct Mailbox *change_folder_notmuch(struct Menu *menu, char *buf, int buflen, int *oldcount,
                                      const struct CurrentEmail *cur, bool read_only)
{
  if (!nm_url_from_query(NULL, buf, buflen))
  {
    mutt_message(_("Failed to create query, aborting"));
    return NULL;
  }

  struct Mailbox *m_query = mx_path_resolve(buf);
  change_folder_mailbox(menu, m_query, oldcount, cur, read_only);
  return m_query;
}
#endif

/**
 * change_folder_string - Change to a different Mailbox by string
 * @param menu         Current Menu
 * @param buf          Folder to change to
 * @param buflen       Length of buffer
 * @param oldcount     How many items are currently in the index
 * @param cur          Remember our place in the index
 * @param pager_return Return to the pager afterwards
 * @param read_only    Open Mailbox in read-only mode
 */
void change_folder_string(struct Menu *menu, char *buf, size_t buflen, int *oldcount,
                          const struct CurrentEmail *cur, bool *pager_return, bool read_only)
{
#ifdef USE_NNTP
  if (OptNews)
  {
    OptNews = false;
    nntp_expand_path(buf, buflen, &CurrentNewsSrv->conn->account);
  }
  else
#endif
  {
    const char *c_folder = cs_subset_string(NeoMutt->sub, "folder");
    mx_path_canon(buf, buflen, c_folder, NULL);
  }

  enum MailboxType type = mx_path_probe(buf);
  if ((type == MUTT_MAILBOX_ERROR) || (type == MUTT_UNKNOWN))
  {
    // Look for a Mailbox by its description, before failing
    struct Mailbox *m = mailbox_find_name(buf);
    if (m)
    {
      change_folder_mailbox(menu, m, oldcount, cur, read_only);
      *pager_return = false;
    }
    else
      mutt_error(_("%s is not a mailbox"), buf);
    return;
  }

  /* past this point, we don't return to the pager on error */
  *pager_return = false;

  struct Mailbox *m = mx_path_resolve(buf);
  change_folder_mailbox(menu, m, oldcount, cur, read_only);
}

/**
 * index_make_entry - Format a menu item for the index list - Implements Menu::make_entry()
 */
void index_make_entry(char *buf, size_t buflen, struct Menu *menu, int line)
{
  buf[0] = '\0';

  struct Mailbox *m = ctx_mailbox(Contex2);

  if (!m || !menu || (line < 0) || (line >= m->email_max))
    return;

  struct Email *e = mutt_get_virt_email(m, line);
  if (!e)
    return;

  MuttFormatFlags flags = MUTT_FORMAT_ARROWCURSOR | MUTT_FORMAT_INDEX;
  struct MuttThread *tmp = NULL;

  const short c_sort = cs_subset_sort(NeoMutt->sub, "sort");
  if (((c_sort & SORT_MASK) == SORT_THREADS) && e->tree)
  {
    flags |= MUTT_FORMAT_TREE; /* display the thread tree */
    if (e->display_subject)
      flags |= MUTT_FORMAT_FORCESUBJ;
    else
    {
      const int reverse = c_sort & SORT_REVERSE;
      int edgemsgno;
      if (reverse)
      {
        if (menu->top + menu->pagelen > menu->max)
          edgemsgno = m->v2r[menu->max - 1];
        else
          edgemsgno = m->v2r[menu->top + menu->pagelen - 1];
      }
      else
        edgemsgno = m->v2r[menu->top];

      for (tmp = e->thread->parent; tmp; tmp = tmp->parent)
      {
        if (!tmp->message)
          continue;

        /* if no ancestor is visible on current screen, provisionally force
         * subject... */
        if (reverse ? (tmp->message->msgno > edgemsgno) : (tmp->message->msgno < edgemsgno))
        {
          flags |= MUTT_FORMAT_FORCESUBJ;
          break;
        }
        else if (tmp->message->vnum >= 0)
          break;
      }
      if (flags & MUTT_FORMAT_FORCESUBJ)
      {
        for (tmp = e->thread->prev; tmp; tmp = tmp->prev)
        {
          if (!tmp->message)
            continue;

          /* ...but if a previous sibling is available, don't force it */
          if (reverse ? (tmp->message->msgno > edgemsgno) : (tmp->message->msgno < edgemsgno))
            break;
          else if (tmp->message->vnum >= 0)
          {
            flags &= ~MUTT_FORMAT_FORCESUBJ;
            break;
          }
        }
      }
    }
  }

  const char *c_index_format = cs_subset_string(NeoMutt->sub, "index_format");
  mutt_make_string(buf, buflen, menu->win_index->state.cols, NONULL(c_index_format),
                   m, Contex2->msg_in_pager, e, flags, NULL);
}

/**
 * index_color - Calculate the colour for a line of the index - Implements Menu::color()
 */
int index_color(int line)
{
  struct Mailbox *m = ctx_mailbox(Contex2);
  if (!m || (line < 0))
    return 0;

  struct Email *e = mutt_get_virt_email(m, line);
  if (!e)
    return 0;

  if (e->pair)
    return e->pair;

  mutt_set_header_color(m, e);
  return e->pair;
}

/**
 * mutt_draw_statusline - Draw a highlighted status bar
 * @param cols   Maximum number of screen columns
 * @param buf    Message to be displayed
 * @param buflen Length of the buffer
 *
 * Users configure the highlighting of the status bar, e.g.
 *     color status red default "[0-9][0-9]:[0-9][0-9]"
 *
 * Where regexes overlap, the one nearest the start will be used.
 * If two regexes start at the same place, the longer match will be used.
 */
void mutt_draw_statusline(int cols, const char *buf, size_t buflen)
{
  if (!buf || !stdscr)
    return;

  size_t i = 0;
  size_t offset = 0;
  bool found = false;
  size_t chunks = 0;
  size_t len = 0;

  struct StatusSyntax
  {
    int color;
    int first;
    int last;
  } *syntax = NULL;

  do
  {
    struct ColorLine *cl = NULL;
    found = false;

    if (!buf[offset])
      break;

    /* loop through each "color status regex" */
    STAILQ_FOREACH(cl, &Colors->status_list, entries)
    {
      regmatch_t pmatch[cl->match + 1];

      if (regexec(&cl->regex, buf + offset, cl->match + 1, pmatch, 0) != 0)
        continue; /* regex doesn't match the status bar */

      int first = pmatch[cl->match].rm_so + offset;
      int last = pmatch[cl->match].rm_eo + offset;

      if (first == last)
        continue; /* ignore an empty regex */

      if (!found)
      {
        chunks++;
        mutt_mem_realloc(&syntax, chunks * sizeof(struct StatusSyntax));
      }

      i = chunks - 1;
      if (!found || (first < syntax[i].first) ||
          ((first == syntax[i].first) && (last > syntax[i].last)))
      {
        syntax[i].color = cl->pair;
        syntax[i].first = first;
        syntax[i].last = last;
      }
      found = true;
    }

    if (syntax)
    {
      offset = syntax[i].last;
    }
  } while (found);

  /* Only 'len' bytes will fit into 'cols' screen columns */
  len = mutt_wstr_trunc(buf, buflen, cols, NULL);

  offset = 0;

  if ((chunks > 0) && (syntax[0].first > 0))
  {
    /* Text before the first highlight */
    mutt_window_addnstr(buf, MIN(len, syntax[0].first));
    attrset(Colors->defs[MT_COLOR_STATUS]);
    if (len <= syntax[0].first)
      goto dsl_finish; /* no more room */

    offset = syntax[0].first;
  }

  for (i = 0; i < chunks; i++)
  {
    /* Highlighted text */
    attrset(syntax[i].color);
    mutt_window_addnstr(buf + offset, MIN(len, syntax[i].last) - offset);
    if (len <= syntax[i].last)
      goto dsl_finish; /* no more room */

    size_t next;
    if ((i + 1) == chunks)
    {
      next = len;
    }
    else
    {
      next = MIN(len, syntax[i + 1].first);
    }

    attrset(Colors->defs[MT_COLOR_STATUS]);
    offset = syntax[i].last;
    mutt_window_addnstr(buf + offset, next - offset);

    offset = next;
    if (offset >= len)
      goto dsl_finish; /* no more room */
  }

  attrset(Colors->defs[MT_COLOR_STATUS]);
  if (offset < len)
  {
    /* Text after the last highlight */
    mutt_window_addnstr(buf + offset, len - offset);
  }

  int width = mutt_strwidth(buf);
  if (width < cols)
  {
    /* Pad the rest of the line with whitespace */
    mutt_paddstr(cols - width, "");
  }
dsl_finish:
  FREE(&syntax);
}

/**
 * index_custom_redraw - Redraw the index - Implements Menu::custom_redraw()
 */
static void index_custom_redraw(struct Menu *menu)
{
  if (menu->redraw & REDRAW_FULL)
  {
    menu_redraw_full(menu);
    mutt_show_error();
  }

  struct Mailbox *m = ctx_mailbox(Contex2);
  if (m && m->emails && !(menu->current >= m->vcount))
  {
    menu_check_recenter(menu);

    if (menu->redraw & REDRAW_INDEX)
    {
      menu_redraw_index(menu);
      menu->redraw |= REDRAW_STATUS;
    }
    else if (menu->redraw & (REDRAW_MOTION_RESYNC | REDRAW_MOTION))
      menu_redraw_motion(menu);
    else if (menu->redraw & REDRAW_CURRENT)
      menu_redraw_current(menu);
  }

  if (menu->redraw & REDRAW_STATUS)
  {
    char buf[1024];
    const char *c_status_format =
        cs_subset_string(NeoMutt->sub, "status_format");
    menu_status_line(buf, sizeof(buf), menu, m, NONULL(c_status_format));
    mutt_window_move(menu->win_ibar, 0, 0);
    mutt_curses_set_color(MT_COLOR_STATUS);
    mutt_draw_statusline(menu->win_ibar->state.cols, buf, sizeof(buf));
    mutt_curses_set_color(MT_COLOR_NORMAL);
    menu->redraw &= ~REDRAW_STATUS;
    const bool c_ts_enabled = cs_subset_bool(NeoMutt->sub, "ts_enabled");
    if (c_ts_enabled && TsSupported)
    {
      const char *c_ts_status_format =
          cs_subset_string(NeoMutt->sub, "ts_status_format");
      menu_status_line(buf, sizeof(buf), menu, m, NONULL(c_ts_status_format));
      mutt_ts_status(buf);
      const char *c_ts_icon_format =
          cs_subset_string(NeoMutt->sub, "ts_icon_format");
      menu_status_line(buf, sizeof(buf), menu, m, NONULL(c_ts_icon_format));
      mutt_ts_icon(buf);
    }
  }

  menu->redraw = REDRAW_NO_FLAGS;
}

/**
 * mutt_index_menu - Display a list of emails
 * @param dlg Dialog containing Windows to draw on
 * @retval num How the menu was finished, e.g. OP_QUIT, OP_EXIT
 *
 * This function handles the message index window as well as commands returned
 * from the pager (MENU_PAGER).
 */
int mutt_index_menu(struct MuttWindow *dlg)
{
  int op = OP_NULL;
  struct IndexData *idata = dlg->wdata;

  idata->done = false;
  idata->tag = false;
  idata->newcount = -1;
  idata->oldcount = -1;
  idata->do_mailbox_notify = true;
  idata->close = 0;
  idata->attach_msg = OptAttachMsg;
  idata->in_pager = false;
  idata->ctx = Contex2;

  struct MuttWindow *win_index = mutt_window_find(dlg, WT_INDEX);
  struct MuttWindow *win_ibar = mutt_window_find(dlg, WT_INDEX_BAR);
  // struct MuttWindow *win_pager = mutt_window_find(dlg, WT_PAGER);
  // struct MuttWindow *win_pbar = mutt_window_find(dlg, WT_PAGER_BAR);

#ifdef USE_NNTP
  if (ctx_mailbox(idata->ctx) && (idata->ctx->mailbox->type == MUTT_NNTP))
    dlg->help_data = IndexNewsHelp;
  else
#endif
    dlg->help_data = IndexHelp;
  dlg->help_menu = MENU_MAIN;

  struct Menu *menu = mutt_menu_new(MENU_MAIN);
  menu->pagelen = win_index->state.rows;
  menu->win_index = win_index;
  menu->win_ibar = win_ibar;

  menu->make_entry = index_make_entry;
  menu->color = index_color;
  menu->current = idata->ctx ? ci_first_message(idata->ctx->mailbox) : 0;
  menu->custom_redraw = index_custom_redraw;
  mutt_menu_push_current(menu);
  mutt_window_reflow(NULL);

  if (!idata->attach_msg)
  {
    /* force the mailbox check after we enter the folder */
    mutt_mailbox_check(ctx_mailbox(idata->ctx), MUTT_MAILBOX_CHECK_FORCE);
  }
#ifdef USE_INOTIFY
  mutt_monitor_add(NULL);
#endif

  short c_sort = cs_subset_sort(NeoMutt->sub, "sort");
  bool c_collapse_all = cs_subset_bool(NeoMutt->sub, "collapse_all");
  if (((c_sort & SORT_MASK) == SORT_THREADS) && c_collapse_all)
  {
    collapse_all(idata->ctx, menu, 0);
    menu->redraw = REDRAW_FULL;
  }

  while (true)
  {
    /* Clear the tag prefix unless we just started it.  Don't clear
     * the prefix on a timeout (op==-2), but do clear on an abort (op==-1) */
    if (idata->tag && (op != OP_TAG_PREFIX) && (op != OP_TAG_PREFIX_COND) && (op != -2))
      idata->tag = false;

    /* check if we need to resort the index because just about
     * any 'op' below could do mutt_enter_command(), either here or
     * from any new menu launched, and change $sort/$sort_aux */
    if (OptNeedResort && ctx_mailbox(idata->ctx) &&
        (idata->ctx->mailbox->msg_count != 0) && (menu->current >= 0))
    {
      resort_index(idata->ctx, menu);
    }

    menu->max = ctx_mailbox(idata->ctx) ? idata->ctx->mailbox->vcount : 0;
    idata->oldcount = ctx_mailbox(idata->ctx) ? idata->ctx->mailbox->msg_count : 0;

    c_sort = cs_subset_sort(NeoMutt->sub, "sort");
    if (OptRedrawTree && ctx_mailbox(idata->ctx) &&
        (idata->ctx->mailbox->msg_count != 0) && ((c_sort & SORT_MASK) == SORT_THREADS))
    {
      mutt_draw_tree(idata->ctx->threads);
      menu->redraw |= REDRAW_STATUS;
      OptRedrawTree = false;
    }

    if (ctx_mailbox(idata->ctx))
    {
      idata->ctx->menu = menu;
      /* check for new mail in the mailbox.  If nonzero, then something has
       * changed about the file (either we got new mail or the file was
       * modified underneath us.) */
      enum MxStatus check = mx_mbox_check(idata->ctx->mailbox);

      if (check == MX_STATUS_ERROR)
      {
        if (mutt_buffer_is_empty(&idata->ctx->mailbox->pathbuf))
        {
          /* fatal error occurred */
          ctx_free(&idata->ctx);
          menu->redraw = REDRAW_FULL;
        }

        OptSearchInvalid = true;
      }
      else if ((check == MX_STATUS_NEW_MAIL) || (check == MX_STATUS_REOPENED) ||
               (check == MX_STATUS_FLAGS))
      {
        /* notify the user of new mail */
        if (check == MX_STATUS_REOPENED)
        {
          mutt_error(
              _("Mailbox was externally modified.  Flags may be wrong."));
        }
        else if (check == MX_STATUS_NEW_MAIL)
        {
          for (size_t i = 0; i < idata->ctx->mailbox->msg_count; i++)
          {
            const struct Email *e = idata->ctx->mailbox->emails[i];
            if (e && !e->read && !e->old)
            {
              mutt_message(_("New mail in this mailbox"));
              const bool c_beep_new = cs_subset_bool(NeoMutt->sub, "beep_new");
              if (c_beep_new)
                mutt_beep(true);
              const char *c_new_mail_command =
                  cs_subset_string(NeoMutt->sub, "new_mail_command");
              if (c_new_mail_command)
              {
                char cmd[1024];
                menu_status_line(cmd, sizeof(cmd), menu, idata->ctx->mailbox,
                                 NONULL(c_new_mail_command));
                if (mutt_system(cmd) != 0)
                  mutt_error(_("Error running \"%s\""), cmd);
              }
              break;
            }
          }
        }
        else if (check == MX_STATUS_FLAGS)
        {
          mutt_message(_("Mailbox was externally modified"));
        }

        /* avoid the message being overwritten by mailbox */
        idata->do_mailbox_notify = false;

        bool verbose = idata->ctx->mailbox->verbose;
        idata->ctx->mailbox->verbose = false;
        update_index(menu, idata->ctx, check, idata->oldcount, &idata->cur);
        idata->ctx->mailbox->verbose = verbose;
        menu->max = idata->ctx->mailbox->vcount;
        menu->redraw = REDRAW_FULL;
        OptSearchInvalid = true;
      }

      if (idata->ctx)
      {
        set_current_email(&idata->cur,
                          mutt_get_virt_email(idata->ctx->mailbox, menu->current));
      }
    }

    if (!idata->attach_msg)
    {
      struct Mailbox *m = idata->ctx ? idata->ctx->mailbox : NULL;
      /* check for new mail in the incoming folders */
      idata->oldcount = idata->newcount;
      idata->newcount = mutt_mailbox_check(m, 0);
      if (idata->newcount != idata->oldcount)
        menu->redraw |= REDRAW_STATUS;
      if (idata->do_mailbox_notify)
      {
        if (mutt_mailbox_notify(m))
        {
          menu->redraw |= REDRAW_STATUS;
          const bool c_beep_new = cs_subset_bool(NeoMutt->sub, "beep_new");
          if (c_beep_new)
            mutt_beep(true);
          const char *c_new_mail_command =
              cs_subset_string(NeoMutt->sub, "new_mail_command");
          if (c_new_mail_command)
          {
            char cmd[1024];
            menu_status_line(cmd, sizeof(cmd), menu, m, NONULL(c_new_mail_command));
            if (mutt_system(cmd) != 0)
              mutt_error(_("Error running \"%s\""), cmd);
          }
        }
      }
      else
        idata->do_mailbox_notify = true;
    }

    if (op >= 0)
      mutt_curses_set_cursor(MUTT_CURSOR_INVISIBLE);

    if (idata->in_pager)
    {
      if (menu->current < menu->max)
        menu->oldcurrent = menu->current;
      else
        menu->oldcurrent = -1;

      mutt_curses_set_cursor(MUTT_CURSOR_VISIBLE); /* fallback from the pager */
    }
    else
    {
      index_custom_redraw(menu);
      window_redraw(RootWindow, false);

      /* give visual indication that the next command is a tag- command */
      if (idata->tag)
      {
        mutt_window_mvaddstr(MessageWindow, 0, 0, "tag-");
        mutt_window_clrtoeol(MessageWindow);
      }

      if (menu->current < menu->max)
        menu->oldcurrent = menu->current;
      else
        menu->oldcurrent = -1;

      const bool c_arrow_cursor = cs_subset_bool(NeoMutt->sub, "arrow_cursor");
      const bool c_braille_friendly =
          cs_subset_bool(NeoMutt->sub, "braille_friendly");
      if (c_arrow_cursor)
        mutt_window_move(menu->win_index, 2, menu->current - menu->top);
      else if (c_braille_friendly)
        mutt_window_move(menu->win_index, 0, menu->current - menu->top);
      else
      {
        mutt_window_move(menu->win_index, menu->win_index->state.cols - 1,
                         menu->current - menu->top);
      }
      mutt_refresh();

      if (SigWinch)
      {
        SigWinch = 0;
        mutt_resize_screen();
        menu->top = 0; /* so we scroll the right amount */
        /* force a real complete redraw.  clrtobot() doesn't seem to be able
         * to handle every case without this.  */
        clearok(stdscr, true);
        mutt_window_clearline(MessageWindow, 0);
        continue;
      }

      op = km_dokey(MENU_MAIN);

      /* either user abort or timeout */
      if (op < 0)
      {
        mutt_timeout_hook();
        if (idata->tag)
          mutt_window_clearline(MessageWindow, 0);
        continue;
      }

      mutt_debug(LL_DEBUG1, "Got op %s (%d)\n", OpStrings[op][0], op);

      mutt_curses_set_cursor(MUTT_CURSOR_VISIBLE);

      /* special handling for the tag-prefix function */
      const bool c_auto_tag = cs_subset_bool(NeoMutt->sub, "auto_tag");
      if ((op == OP_TAG_PREFIX) || (op == OP_TAG_PREFIX_COND))
      {
        /* A second tag-prefix command aborts */
        if (idata->tag)
        {
          idata->tag = false;
          mutt_window_clearline(MessageWindow, 0);
          continue;
        }

        if (!ctx_mailbox(idata->ctx))
        {
          mutt_error(_("No mailbox is open"));
          continue;
        }

        if (idata->ctx->mailbox->msg_tagged == 0)
        {
          if (op == OP_TAG_PREFIX)
            mutt_error(_("No tagged messages"));
          else if (op == OP_TAG_PREFIX_COND)
          {
            mutt_flush_macro_to_endcond();
            mutt_message(_("Nothing to do"));
          }
          continue;
        }

        /* get the real command */
        idata->tag = true;
        continue;
      }
      else if (c_auto_tag && ctx_mailbox(idata->ctx) &&
               (idata->ctx->mailbox->msg_tagged != 0))
      {
        idata->tag = true;
      }

      mutt_clear_error();
    }

#ifdef USE_NNTP
    OptNews = false; /* for any case */
#endif

#ifdef USE_NOTMUCH
    nm_db_debug_check(ctx_mailbox(idata->ctx));
#endif

    int rc = -2;
    for (size_t i = 0; IndexFunctions[i].op != OP_NULL; i++)
    {
      const struct IndexFunction *fn = &IndexFunctions[i];
      if (fn->op == op)
      {
        if (!prereq(idata->ctx, menu, fn->flags))
        {
          // rc = -3;
          break;
        }
        rc = IndexFunctions[i].function(menu, op, idata);
        break;
      }
    }

    if (rc == IR_CONTINUE)
    {
      op = OP_DISPLAY_MESSAGE;
      continue;
    }

    if (rc == -2)
    {
    }
    // switch (op)
    // {
    //   default:
    //     if (!idata->in_pager)
    //       km_error_key(MENU_MAIN);
    // }

#ifdef USE_NOTMUCH
    nm_db_debug_check(ctx_mailbox(idata->ctx));
#endif

    if (idata->in_pager)
    {
      mutt_clear_pager_position();
      idata->in_pager = false;
      menu->redraw = REDRAW_FULL;
    }

    if (idata->done)
      break;
  }

  mutt_menu_pop_current(menu);
  mutt_menu_free(&menu);
  return idata->close;
}

/**
 * mutt_set_header_color - Select a colour for a message
 * @param m Mailbox
 * @param e Current Email
 */
void mutt_set_header_color(struct Mailbox *m, struct Email *e)
{
  if (!e)
    return;

  struct ColorLine *color = NULL;
  struct PatternCache cache = { 0 };

  STAILQ_FOREACH(color, &Colors->index_list, entries)
  {
    if (mutt_pattern_exec(SLIST_FIRST(color->color_pattern),
                          MUTT_MATCH_FULL_ADDRESS, m, e, &cache))
    {
      e->pair = color->pair;
      return;
    }
  }
  e->pair = Colors->defs[MT_COLOR_NORMAL];
}

/**
 * mutt_reply_observer - Listen for config changes to "reply_regex" - Implements ::observer_t
 */
int mutt_reply_observer(struct NotifyCallback *nc)
{
  if (!nc->event_data)
    return -1;
  if (nc->event_type != NT_CONFIG)
    return 0;

  struct EventConfig *ec = nc->event_data;

  if (!mutt_str_equal(ec->name, "reply_regex"))
    return 0;

  struct Mailbox *m = ctx_mailbox(Contex2);
  if (!m)
    return 0;

  regmatch_t pmatch[1];

  for (int i = 0; i < m->msg_count; i++)
  {
    struct Email *e = m->emails[i];
    if (!e)
      break;
    struct Envelope *env = e->env;
    if (!env || !env->subject)
      continue;

    const struct Regex *c_reply_regex =
        cs_subset_regex(NeoMutt->sub, "reply_regex");
    if (mutt_regex_capture(c_reply_regex, env->subject, 1, pmatch))
    {
      env->real_subj = env->subject + pmatch[0].rm_eo;
      continue;
    }

    env->real_subj = env->subject;
  }

  OptResortInit = true; /* trigger a redraw of the index */
  return 0;
}

/**
 * create_panel_index - Create the Windows for the Index panel
 * @param parent        Parent Window
 * @param status_on_top true, if the Index bar should be on top
 * @retval ptr Nested Windows
 */
static struct MuttWindow *create_panel_index(struct MuttWindow *parent, bool status_on_top)
{
  struct MuttWindow *panel_index =
      mutt_window_new(WT_CONTAINER, MUTT_WIN_ORIENT_VERTICAL, MUTT_WIN_SIZE_MAXIMISE,
                      MUTT_WIN_SIZE_UNLIMITED, MUTT_WIN_SIZE_UNLIMITED);
  parent->focus = panel_index;

  struct MuttWindow *win_index =
      mutt_window_new(WT_INDEX, MUTT_WIN_ORIENT_VERTICAL, MUTT_WIN_SIZE_MAXIMISE,
                      MUTT_WIN_SIZE_UNLIMITED, MUTT_WIN_SIZE_UNLIMITED);
  panel_index->focus = win_index;

  struct MuttWindow *win_ibar =
      mutt_window_new(WT_INDEX_BAR, MUTT_WIN_ORIENT_VERTICAL,
                      MUTT_WIN_SIZE_FIXED, MUTT_WIN_SIZE_UNLIMITED, 1);

  if (status_on_top)
  {
    mutt_window_add_child(panel_index, win_ibar);
    mutt_window_add_child(panel_index, win_index);
  }
  else
  {
    mutt_window_add_child(panel_index, win_index);
    mutt_window_add_child(panel_index, win_ibar);
  }

  return panel_index;
}

/**
 * create_panel_pager - Create the Windows for the Pager panel
 * @param parent        Parent Window
 * @param status_on_top true, if the Pager bar should be on top
 * @retval ptr Nested Windows
 */
static struct MuttWindow *create_panel_pager(struct MuttWindow *parent, bool status_on_top)
{
  struct MuttWindow *panel_pager =
      mutt_window_new(WT_CONTAINER, MUTT_WIN_ORIENT_VERTICAL, MUTT_WIN_SIZE_MAXIMISE,
                      MUTT_WIN_SIZE_UNLIMITED, MUTT_WIN_SIZE_UNLIMITED);
  panel_pager->state.visible = false; // The Pager and Pager Bar are initially hidden

  struct MuttWindow *win_pager =
      mutt_window_new(WT_PAGER, MUTT_WIN_ORIENT_VERTICAL, MUTT_WIN_SIZE_MAXIMISE,
                      MUTT_WIN_SIZE_UNLIMITED, MUTT_WIN_SIZE_UNLIMITED);
  panel_pager->focus = win_pager;

  struct MuttWindow *win_pbar =
      mutt_window_new(WT_PAGER_BAR, MUTT_WIN_ORIENT_VERTICAL,
                      MUTT_WIN_SIZE_FIXED, MUTT_WIN_SIZE_UNLIMITED, 1);

  if (status_on_top)
  {
    mutt_window_add_child(panel_pager, win_pbar);
    mutt_window_add_child(panel_pager, win_pager);
  }
  else
  {
    mutt_window_add_child(panel_pager, win_pager);
    mutt_window_add_child(panel_pager, win_pbar);
  }

  return panel_pager;
}

/**
 * index_pager_init - Allocate the Windows for the Index/Pager
 * @param sub ConfigSubset
 * @param ctx Context
 * @retval ptr Dialog containing nested Windows
 */
struct MuttWindow *index_pager_init(struct ConfigSubset *sub, struct Context *ctx)
{
  struct MuttWindow *dlg =
      mutt_window_new(WT_DLG_INDEX, MUTT_WIN_ORIENT_HORIZONTAL, MUTT_WIN_SIZE_MAXIMISE,
                      MUTT_WIN_SIZE_UNLIMITED, MUTT_WIN_SIZE_UNLIMITED);
  notify_observer_add(NeoMutt->notify, NT_CONFIG, mutt_dlgindex_observer, dlg);

  const bool c_status_on_top = cs_subset_bool(NeoMutt->sub, "status_on_top");
  mutt_window_add_child(dlg, create_panel_index(dlg, c_status_on_top));
  mutt_window_add_child(dlg, create_panel_pager(dlg, c_status_on_top));

  struct IndexData *idata = index_data_new();
  idata->sub = sub;
  idata->ctx = ctx;
  idata->mailbox = ctx_mailbox(ctx);
  idata->account = idata->mailbox ? idata->mailbox->account : NULL;

  dlg->wdata = idata;
  dlg->wdata_free = index_data_free;

  return dlg;
}

/**
 * index_pager_shutdown - Clear up any non-Window parts
 * @param dlg Dialog
 */
void index_pager_shutdown(struct MuttWindow *dlg)
{
  notify_observer_remove(NeoMutt->notify, mutt_dlgindex_observer, dlg);
}

/**
 * mutt_dlgindex_observer - Listen for config changes affecting the Index/Pager - Implements ::observer_t
 */
int mutt_dlgindex_observer(struct NotifyCallback *nc)
{
  if (!nc->event_data || !nc->global_data)
    return -1;
  if (nc->event_type != NT_CONFIG)
    return 0;

  struct EventConfig *ec = nc->event_data;
  struct MuttWindow *dlg = nc->global_data;

  struct MuttWindow *win_index = mutt_window_find(dlg, WT_INDEX);
  struct MuttWindow *win_pager = mutt_window_find(dlg, WT_PAGER);
  if (!win_index || !win_pager)
    return -1;

  if (mutt_str_equal(ec->name, "status_on_top"))
  {
    struct MuttWindow *parent = win_index->parent;
    if (!parent)
      return -1;
    struct MuttWindow *first = TAILQ_FIRST(&parent->children);
    if (!first)
      return -1;

    const bool c_status_on_top = cs_subset_bool(NeoMutt->sub, "status_on_top");
    if ((c_status_on_top && (first == win_index)) ||
        (!c_status_on_top && (first != win_index)))
    {
      // Swap the Index and the Index Bar Windows
      TAILQ_REMOVE(&parent->children, first, entries);
      TAILQ_INSERT_TAIL(&parent->children, first, entries);
    }

    parent = win_pager->parent;
    first = TAILQ_FIRST(&parent->children);

    if ((c_status_on_top && (first == win_pager)) ||
        (!c_status_on_top && (first != win_pager)))
    {
      // Swap the Pager and Pager Bar Windows
      TAILQ_REMOVE(&parent->children, first, entries);
      TAILQ_INSERT_TAIL(&parent->children, first, entries);
    }
    goto reflow;
  }

  if (mutt_str_equal(ec->name, "pager_index_lines"))
  {
    struct MuttWindow *parent = win_pager->parent;
    if (parent->state.visible)
    {
      const short c_pager_index_lines =
          cs_subset_number(NeoMutt->sub, "pager_index_lines");
      int vcount = ctx_mailbox(Contex2) ? Contex2->mailbox->vcount : 0;
      win_index->req_rows = MIN(c_pager_index_lines, vcount);
      win_index->size = MUTT_WIN_SIZE_FIXED;

      win_index->parent->size = MUTT_WIN_SIZE_MINIMISE;
      win_index->parent->state.visible = (c_pager_index_lines != 0);
    }
    else
    {
      win_index->req_rows = MUTT_WIN_SIZE_UNLIMITED;
      win_index->size = MUTT_WIN_SIZE_MAXIMISE;

      win_index->parent->size = MUTT_WIN_SIZE_MAXIMISE;
      win_index->parent->state.visible = true;
    }
  }

reflow:
  mutt_window_reflow(dlg);
  return 0;
}
