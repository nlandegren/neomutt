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
#include "hdrline.h"
#include "hook.h"
#include "ibar.h"
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
static const struct Mapping IndexNewsHelp[] = {
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

// clang-format off
/**
 * typedef CheckFlags - Checks to perform before running a function
 */
typedef uint8_t CheckFlags;       ///< Flags, e.g. #CHECK_IN_MAILBOX
#define CHECK_NO_FLAGS         0  ///< No flags are set
#define CHECK_IN_MAILBOX (1 << 0) ///< Is there a mailbox open?
#define CHECK_MSGCOUNT   (1 << 1) ///< Are there any messages?
#define CHECK_VISIBLE    (1 << 2) ///< Is the selected message visible in the index?
#define CHECK_READONLY   (1 << 3) ///< Is the mailbox readonly?
#define CHECK_ATTACH     (1 << 4) ///< Is the user in message-attach mode?
// clang-format on

/**
 * prereq - Check the pre-requisites for a function
 * @param ctx    Mailbox
 * @param menu   Current Menu
 * @param checks Checks to perform, see #CheckFlags
 * @retval bool true if the checks pass successfully
 */
static bool prereq(struct Context *ctx, struct Menu *menu, CheckFlags checks)
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
static bool check_acl(struct Mailbox *m, AclFlags acl, const char *msg)
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
static void collapse_all(struct Context *ctx, struct Menu *menu, int toggle)
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
static int ci_next_undeleted(struct Mailbox *m, int msgno)
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
static int ci_previous_undeleted(struct Mailbox *m, int msgno)
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
static int ci_first_message(struct Mailbox *m)
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
static int mx_toggle_write(struct Mailbox *m)
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
static void resort_index(struct Context *ctx, struct Menu *menu)
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
static void set_current_email(struct CurrentEmail *cur, struct Email *e)
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
static void update_index(struct Menu *menu, struct Context *ctx, enum MxStatus check,
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
static void change_folder_mailbox(struct Menu *menu, struct Mailbox *m, int *oldcount,
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
static struct Mailbox *change_folder_notmuch(struct Menu *menu, char *buf,
                                             int buflen, int *oldcount,
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
static void change_folder_string(struct Menu *menu, char *buf, size_t buflen,
                                 int *oldcount, const struct CurrentEmail *cur,
                                 bool *pager_return, bool read_only)
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

  struct MuttWindow *win_index = mutt_window_find(dlg, WT_INDEX);
  struct MuttWindow *win_ibar = mutt_window_find(dlg, WT_INDEX_BAR);
  struct MuttWindow *win_pager = mutt_window_find(dlg, WT_PAGER);
  struct MuttWindow *win_pbar = mutt_window_find(dlg, WT_PAGER_BAR);

#ifdef USE_NNTP
  if (ctx_mailbox(Contex2) && (Contex2->mailbox->type == MUTT_NNTP))
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
  menu->current = Contex2 ? ci_first_message(Contex2->mailbox) : 0;
  menu->custom_redraw = index_custom_redraw;
  mutt_menu_push_current(menu);
  mutt_window_reflow(NULL);

  if (!idata->attach_msg)
  {
    /* force the mailbox check after we enter the folder */
    mutt_mailbox_check(ctx_mailbox(Contex2), MUTT_MAILBOX_CHECK_FORCE);
  }
#ifdef USE_INOTIFY
  mutt_monitor_add(NULL);
#endif

  short c_sort = cs_subset_sort(NeoMutt->sub, "sort");
  bool c_collapse_all = cs_subset_bool(NeoMutt->sub, "collapse_all");
  if (((c_sort & SORT_MASK) == SORT_THREADS) && c_collapse_all)
  {
    collapse_all(Contex2, menu, 0);
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
    if (OptNeedResort && ctx_mailbox(Contex2) &&
        (Contex2->mailbox->msg_count != 0) && (menu->current >= 0))
    {
      resort_index(Contex2, menu);
    }

    menu->max = ctx_mailbox(Contex2) ? Contex2->mailbox->vcount : 0;
    idata->oldcount = ctx_mailbox(Contex2) ? Contex2->mailbox->msg_count : 0;

    c_sort = cs_subset_sort(NeoMutt->sub, "sort");
    if (OptRedrawTree && ctx_mailbox(Contex2) && (Contex2->mailbox->msg_count != 0) &&
        ((c_sort & SORT_MASK) == SORT_THREADS))
    {
      mutt_draw_tree(Contex2->threads);
      menu->redraw |= REDRAW_STATUS;
      OptRedrawTree = false;
    }

    if (ctx_mailbox(Contex2))
    {
      Contex2->menu = menu;
      /* check for new mail in the mailbox.  If nonzero, then something has
       * changed about the file (either we got new mail or the file was
       * modified underneath us.) */
      enum MxStatus check = mx_mbox_check(Contex2->mailbox);

      if (check == MX_STATUS_ERROR)
      {
        if (mutt_buffer_is_empty(&Contex2->mailbox->pathbuf))
        {
          /* fatal error occurred */
          ctx_free(&Contex2);
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
          for (size_t i = 0; i < Contex2->mailbox->msg_count; i++)
          {
            const struct Email *e = Contex2->mailbox->emails[i];
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
                menu_status_line(cmd, sizeof(cmd), menu, Contex2->mailbox,
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

        bool verbose = Contex2->mailbox->verbose;
        Contex2->mailbox->verbose = false;
        update_index(menu, Contex2, check, idata->oldcount, &idata->cur);
        Contex2->mailbox->verbose = verbose;
        menu->max = Contex2->mailbox->vcount;
        menu->redraw = REDRAW_FULL;
        OptSearchInvalid = true;
      }

      if (Contex2)
      {
        set_current_email(&idata->cur, mutt_get_virt_email(Contex2->mailbox, menu->current));
      }
    }

    if (!idata->attach_msg)
    {
      struct Mailbox *m = Contex2 ? Contex2->mailbox : NULL;
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

        if (!ctx_mailbox(Contex2))
        {
          mutt_error(_("No mailbox is open"));
          continue;
        }

        if (Contex2->mailbox->msg_tagged == 0)
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
      else if (c_auto_tag && ctx_mailbox(Contex2) && (Contex2->mailbox->msg_tagged != 0))
      {
        idata->tag = true;
      }

      mutt_clear_error();
    }

#ifdef USE_NNTP
    OptNews = false; /* for any case */
#endif

#ifdef USE_NOTMUCH
    if (Contex2)
      nm_db_debug_check(Contex2->mailbox);
#endif

    switch (op)
    {
        /* ----------------------------------------------------------------------
         * movement commands
         */

      case OP_BOTTOM_PAGE:
        menu_bottom_page(menu);
        break;
      case OP_CURRENT_BOTTOM:
        menu_current_bottom(menu);
        break;
      case OP_CURRENT_MIDDLE:
        menu_current_middle(menu);
        break;
      case OP_CURRENT_TOP:
        menu_current_top(menu);
        break;
      case OP_FIRST_ENTRY:
        menu_first_entry(menu);
        break;
      case OP_HALF_DOWN:
        menu_half_down(menu);
        break;
      case OP_HALF_UP:
        menu_half_up(menu);
        break;
      case OP_LAST_ENTRY:
        menu_last_entry(menu);
        break;
      case OP_MIDDLE_PAGE:
        menu_middle_page(menu);
        break;
      case OP_NEXT_LINE:
        menu_next_line(menu);
        break;
      case OP_NEXT_PAGE:
        menu_next_page(menu);
        break;
      case OP_PREV_LINE:
        menu_prev_line(menu);
        break;
      case OP_PREV_PAGE:
        menu_prev_page(menu);
        break;
      case OP_TOP_PAGE:
        menu_top_page(menu);
        break;

#ifdef USE_NNTP
      case OP_GET_PARENT:
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE))
          break;
        /* fallthrough */

      case OP_GET_MESSAGE:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_READONLY | CHECK_ATTACH))
          break;
        char buf[PATH_MAX] = { 0 };
        if (Contex2->mailbox->type == MUTT_NNTP)
        {
          if (op == OP_GET_MESSAGE)
          {
            if ((mutt_get_field(_("Enter Message-Id: "), buf, sizeof(buf),
                                MUTT_COMP_NO_FLAGS, false, NULL, NULL) != 0) ||
                (buf[0] == '\0'))
            {
              break;
            }
          }
          else
          {
            if (!idata->cur.e || STAILQ_EMPTY(&idata->cur.e->env->references))
            {
              mutt_error(_("Article has no parent reference"));
              break;
            }
            mutt_str_copy(buf, STAILQ_FIRST(&idata->cur.e->env->references)->data,
                          sizeof(buf));
          }
          if (!Contex2->mailbox->id_hash)
            Contex2->mailbox->id_hash = mutt_make_id_hash(Contex2->mailbox);
          struct Email *e = mutt_hash_find(Contex2->mailbox->id_hash, buf);
          if (e)
          {
            if (e->vnum != -1)
            {
              menu->current = e->vnum;
              menu->redraw = REDRAW_MOTION_RESYNC;
            }
            else if (e->collapsed)
            {
              mutt_uncollapse_thread(e);
              mutt_set_vnum(Contex2->mailbox);
              menu->current = e->vnum;
              menu->redraw = REDRAW_MOTION_RESYNC;
            }
            else
              mutt_error(_("Message is not visible in limited view"));
          }
          else
          {
            mutt_message(_("Fetching %s from server..."), buf);
            int rc = nntp_check_msgid(Contex2->mailbox, buf);
            if (rc == 0)
            {
              e = Contex2->mailbox->emails[Contex2->mailbox->msg_count - 1];
              mutt_sort_headers(Contex2->mailbox, Contex2->threads, false,
                                &Contex2->vsize);
              menu->current = e->vnum;
              menu->redraw = REDRAW_FULL;
            }
            else if (rc > 0)
              mutt_error(_("Article %s not found on the server"), buf);
          }
        }
        break;
      }

      case OP_GET_CHILDREN:
      case OP_RECONSTRUCT_THREAD:
      {
        if (!prereq(Contex2, menu,
                    CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY | CHECK_ATTACH))
        {
          break;
        }
        if (Contex2->mailbox->type != MUTT_NNTP)
          break;

        if (!idata->cur.e)
          break;

        char buf[PATH_MAX] = { 0 };
        int oldmsgcount = Contex2->mailbox->msg_count;
        int oldindex = idata->cur.e->index;
        int rc = 0;

        if (!idata->cur.e->env->message_id)
        {
          mutt_error(_("No Message-Id. Unable to perform operation."));
          break;
        }

        mutt_message(_("Fetching message headers..."));
        if (!Contex2->mailbox->id_hash)
          Contex2->mailbox->id_hash = mutt_make_id_hash(Contex2->mailbox);
        mutt_str_copy(buf, idata->cur.e->env->message_id, sizeof(buf));

        /* trying to find msgid of the root message */
        if (op == OP_RECONSTRUCT_THREAD)
        {
          struct ListNode *ref = NULL;
          STAILQ_FOREACH(ref, &idata->cur.e->env->references, entries)
          {
            if (!mutt_hash_find(Contex2->mailbox->id_hash, ref->data))
            {
              rc = nntp_check_msgid(Contex2->mailbox, ref->data);
              if (rc < 0)
                break;
            }

            /* the last msgid in References is the root message */
            if (!STAILQ_NEXT(ref, entries))
              mutt_str_copy(buf, ref->data, sizeof(buf));
          }
        }

        /* fetching all child messages */
        if (rc >= 0)
          rc = nntp_check_children(Contex2->mailbox, buf);

        /* at least one message has been loaded */
        if (Contex2->mailbox->msg_count > oldmsgcount)
        {
          struct Email *e_oldcur = mutt_get_virt_email(Contex2->mailbox, menu->current);
          bool verbose = Contex2->mailbox->verbose;

          if (rc < 0)
            Contex2->mailbox->verbose = false;
          mutt_sort_headers(Contex2->mailbox, Contex2->threads,
                            (op == OP_RECONSTRUCT_THREAD), &Contex2->vsize);
          Contex2->mailbox->verbose = verbose;

          /* Similar to OP_MAIN_ENTIRE_THREAD, keep displaying the old message, but
            * update the index */
          if (idata->in_pager)
          {
            menu->current = e_oldcur->vnum;
            menu->redraw = REDRAW_STATUS | REDRAW_INDEX;
            op = OP_DISPLAY_MESSAGE;
            continue;
          }

          /* if the root message was retrieved, move to it */
          struct Email *e = mutt_hash_find(Contex2->mailbox->id_hash, buf);
          if (e)
            menu->current = e->vnum;
          else
          {
            /* try to restore old position */
            for (int i = 0; i < Contex2->mailbox->msg_count; i++)
            {
              e = Contex2->mailbox->emails[i];
              if (!e)
                break;
              if (e->index == oldindex)
              {
                menu->current = e->vnum;
                /* as an added courtesy, recenter the menu
                  * with the current entry at the middle of the screen */
                menu_check_recenter(menu);
                menu_current_middle(menu);
              }
            }
          }
          menu->redraw = REDRAW_FULL;
        }
        else if (rc >= 0)
        {
          mutt_error(_("No deleted messages found in the thread"));
          /* Similar to OP_MAIN_ENTIRE_THREAD, keep displaying the old message, but
            * update the index */
          if (idata->in_pager)
          {
            op = OP_DISPLAY_MESSAGE;
            continue;
          }
        }
        break;
      }
#endif

      case OP_JUMP:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX))
          break;
        char buf[PATH_MAX] = { 0 };
        int msg_num = 0;
        if (isdigit(LastKey))
          mutt_unget_event(LastKey, 0);
        if ((mutt_get_field(_("Jump to message: "), buf, sizeof(buf),
                            MUTT_COMP_NO_FLAGS, false, NULL, NULL) != 0) ||
            (buf[0] == '\0'))
        {
          mutt_error(_("Nothing to do"));
        }
        else if (mutt_str_atoi(buf, &msg_num) < 0)
          mutt_error(_("Argument must be a message number"));
        else if ((msg_num < 1) || (msg_num > Contex2->mailbox->msg_count))
          mutt_error(_("Invalid message number"));
        else if (!Contex2->mailbox->emails[msg_num - 1]->visible)
          mutt_error(_("That message is not visible"));
        else
        {
          struct Email *e = Contex2->mailbox->emails[msg_num - 1];

          if (mutt_messages_in_thread(Contex2->mailbox, e, MIT_POSITION) > 1)
          {
            mutt_uncollapse_thread(e);
            mutt_set_vnum(Contex2->mailbox);
          }
          menu->current = e->vnum;
        }

        if (idata->in_pager)
        {
          op = OP_DISPLAY_MESSAGE;
          continue;
        }
        else
          menu->redraw = REDRAW_FULL;

        break;
      }

        /* --------------------------------------------------------------------
         * 'index' specific commands
         */

      case OP_MAIN_DELETE_PATTERN:
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_READONLY | CHECK_ATTACH))
        {
          break;
        }
        /* L10N: CHECK_ACL */
        /* L10N: Due to the implementation details we do not know whether we
            delete zero, 1, 12, ... messages. So in English we use
            "messages". Your language might have other means to express this.  */
        if (!check_acl(Contex2->mailbox, MUTT_ACL_DELETE, _("Can't delete messages")))
          break;

        mutt_pattern_func(Contex2, MUTT_DELETE, _("Delete messages matching: "));
        menu->redraw |= REDRAW_INDEX | REDRAW_STATUS;
        break;

#ifdef USE_POP
      case OP_MAIN_FETCH_MAIL:
        if (!prereq(Contex2, menu, CHECK_ATTACH))
          break;
        pop_fetch_mail();
        menu->redraw = REDRAW_FULL;
        break;
#endif /* USE_POP */

      case OP_SHOW_LOG_MESSAGES:
      {
#ifdef USE_DEBUG_GRAPHVIZ
        dump_graphviz("index", Contex2);
#endif
        char tempfile[PATH_MAX];
        mutt_mktemp(tempfile, sizeof(tempfile));

        FILE *fp = mutt_file_fopen(tempfile, "a+");
        if (!fp)
        {
          mutt_perror("fopen");
          break;
        }

        log_queue_save(fp);
        mutt_file_fclose(&fp);

        mutt_do_pager("messages", tempfile, MUTT_PAGER_LOGS, NULL);
        break;
      }

      case OP_HELP:
        mutt_help(MENU_MAIN);
        menu->redraw = REDRAW_FULL;
        break;

      case OP_MAIN_SHOW_LIMIT:
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX))
          break;
        if (!ctx_has_limit(Contex2))
          mutt_message(_("No limit pattern is in effect"));
        else
        {
          char buf2[256];
          /* L10N: ask for a limit to apply */
          snprintf(buf2, sizeof(buf2), _("Limit: %s"), Contex2->pattern);
          mutt_message("%s", buf2);
        }
        break;

      case OP_LIMIT_CURRENT_THREAD:
      case OP_MAIN_LIMIT:
      case OP_TOGGLE_READ:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX))
          break;
        const bool lmt = ctx_has_limit(Contex2);
        menu->oldcurrent = idata->cur.e ? idata->cur.e->index : -1;
        if (op == OP_TOGGLE_READ)
        {
          char buf2[1024];

          if (!lmt || !mutt_strn_equal(Contex2->pattern, "!~R!~D~s", 8))
          {
            snprintf(buf2, sizeof(buf2), "!~R!~D~s%s", lmt ? Contex2->pattern : ".*");
          }
          else
          {
            mutt_str_copy(buf2, Contex2->pattern + 8, sizeof(buf2));
            if ((*buf2 == '\0') || mutt_strn_equal(buf2, ".*", 2))
              snprintf(buf2, sizeof(buf2), "~A");
          }
          mutt_str_replace(&Contex2->pattern, buf2);
          mutt_pattern_func(Contex2, MUTT_LIMIT, NULL);
        }

        if (((op == OP_LIMIT_CURRENT_THREAD) &&
             mutt_limit_current_thread(Contex2, idata->cur.e)) ||
            (op == OP_TOGGLE_READ) ||
            ((op == OP_MAIN_LIMIT) &&
             (mutt_pattern_func(Contex2, MUTT_LIMIT, _("Limit to messages matching: ")) == 0)))
        {
          if (menu->oldcurrent >= 0)
          {
            /* try to find what used to be the current message */
            menu->current = -1;
            for (size_t i = 0; i < Contex2->mailbox->vcount; i++)
            {
              struct Email *e = mutt_get_virt_email(Contex2->mailbox, i);
              if (!e)
                continue;
              if (e->index == menu->oldcurrent)
              {
                menu->current = i;
                break;
              }
            }
            if (menu->current < 0)
              menu->current = 0;
          }
          else
            menu->current = 0;
          if ((Contex2->mailbox->msg_count != 0) && ((C_Sort & SORT_MASK) == SORT_THREADS))
          {
            c_collapse_all = cs_subset_bool(NeoMutt->sub, "collapse_all");
            if (c_collapse_all)
              collapse_all(Contex2, menu, 0);
            mutt_draw_tree(Contex2->threads);
          }
          menu->redraw = REDRAW_FULL;
        }
        if (lmt)
          mutt_message(_("To view all messages, limit to \"all\""));
        break;
      }

      case OP_QUIT:
      {
        idata->close = op;
        if (idata->attach_msg)
        {
          idata->done = true;
          break;
        }

        const enum QuadOption c_quit = cs_subset_quad(NeoMutt->sub, "quit");
        if (query_quadoption(c_quit, _("Quit NeoMutt?")) == MUTT_YES)
        {
          idata->oldcount =
              (Contex2 && Contex2->mailbox) ? Contex2->mailbox->msg_count : 0;

          mutt_startup_shutdown_hook(MUTT_SHUTDOWN_HOOK);
          notify_send(NeoMutt->notify, NT_GLOBAL, NT_GLOBAL_SHUTDOWN, NULL);

          enum MxStatus check = MX_STATUS_OK;
          if (!Contex2 || ((check = mx_mbox_close(&Contex2)) == MX_STATUS_OK))
          {
            idata->done = true;
          }
          else
          {
            if ((check == MX_STATUS_NEW_MAIL) || (check == MX_STATUS_REOPENED))
            {
              update_index(menu, Contex2, check, idata->oldcount, &idata->cur);
            }

            menu->redraw = REDRAW_FULL; /* new mail arrived? */
            OptSearchInvalid = true;
          }
        }
        break;
      }

      case OP_REDRAW:
        mutt_window_reflow(NULL);
        clearok(stdscr, true);
        menu->redraw = REDRAW_FULL;
        break;

      // Initiating a search can happen on an empty mailbox, but
      // searching for next/previous/... needs to be on a message and
      // thus a non-empty mailbox
      case OP_SEARCH_REVERSE:
      case OP_SEARCH_NEXT:
      case OP_SEARCH_OPPOSITE:
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE))
          break;
        /* fallthrough */
      case OP_SEARCH:
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX))
          break;
        menu->current = mutt_search_command(Contex2, Contex2->mailbox, menu->current, op);
        if (menu->current == -1)
          menu->current = menu->oldcurrent;
        else
          menu->redraw |= REDRAW_MOTION;
        break;

      case OP_SORT:
      case OP_SORT_REVERSE:
        if (mutt_select_sort((op == OP_SORT_REVERSE)) != 0)
          break;

        if (ctx_mailbox(Contex2) && (Contex2->mailbox->msg_count != 0))
        {
          resort_index(Contex2, menu);
          OptSearchInvalid = true;
        }
        if (idata->in_pager)
        {
          op = OP_DISPLAY_MESSAGE;
          continue;
        }
        menu->redraw |= REDRAW_STATUS;
        break;

      case OP_TAG:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE))
          break;
        const bool c_auto_tag = cs_subset_bool(NeoMutt->sub, "auto_tag");
        if (idata->tag && !c_auto_tag)
        {
          struct Mailbox *m = Contex2->mailbox;
          for (size_t i = 0; i < m->msg_count; i++)
          {
            struct Email *e = m->emails[i];
            if (!e)
              break;
            if (e->visible)
              mutt_set_flag(m, e, MUTT_TAG, false);
          }
          menu->redraw |= REDRAW_STATUS | REDRAW_INDEX;
        }
        else
        {
          if (!idata->cur.e)
            break;
          mutt_set_flag(Contex2->mailbox, idata->cur.e, MUTT_TAG, !idata->cur.e->tagged);

          menu->redraw |= REDRAW_STATUS;
          const bool c_resolve = cs_subset_bool(NeoMutt->sub, "resolve");
          if (c_resolve && (menu->current < Contex2->mailbox->vcount - 1))
          {
            menu->current++;
            menu->redraw |= REDRAW_MOTION_RESYNC;
          }
          else
            menu->redraw |= REDRAW_CURRENT;
        }
        break;
      }

      case OP_MAIN_TAG_PATTERN:
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX))
          break;
        mutt_pattern_func(Contex2, MUTT_TAG, _("Tag messages matching: "));
        menu->redraw |= REDRAW_INDEX | REDRAW_STATUS;
        break;

      case OP_MAIN_UNDELETE_PATTERN:
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_READONLY))
          break;
        /* L10N: CHECK_ACL */
        /* L10N: Due to the implementation details we do not know whether we
            undelete zero, 1, 12, ... messages. So in English we use
            "messages". Your language might have other means to express this. */
        if (!check_acl(Contex2->mailbox, MUTT_ACL_DELETE, _("Can't undelete messages")))
          break;

        if (mutt_pattern_func(Contex2, MUTT_UNDELETE, _("Undelete messages matching: ")) == 0)
        {
          menu->redraw |= REDRAW_INDEX | REDRAW_STATUS;
        }
        break;

      case OP_MAIN_UNTAG_PATTERN:
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX))
          break;
        if (mutt_pattern_func(Contex2, MUTT_UNTAG, _("Untag messages matching: ")) == 0)
          menu->redraw |= REDRAW_INDEX | REDRAW_STATUS;
        break;

      case OP_COMPOSE_TO_SENDER:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_ATTACH))
          break;
        struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
        el_add_tagged(&el, Contex2, idata->cur.e, idata->tag);
        mutt_send_message(SEND_TO_SENDER, NULL, NULL, Contex2, &el, NeoMutt->sub);
        emaillist_clear(&el);
        menu->redraw = REDRAW_FULL;
        break;
      }

      /* --------------------------------------------------------------------
       * The following operations can be performed inside of the pager.
       */

#ifdef USE_IMAP
      case OP_MAIN_IMAP_FETCH:
        if (ctx_mailbox(Contex2) && (Contex2->mailbox->type == MUTT_IMAP))
          imap_check_mailbox(Contex2->mailbox, true);
        break;

      case OP_MAIN_IMAP_LOGOUT_ALL:
        if (ctx_mailbox(Contex2) && (Contex2->mailbox->type == MUTT_IMAP))
        {
          const enum MxStatus check = mx_mbox_close(&Contex2);
          if (check != MX_STATUS_OK)
          {
            if ((check == MX_STATUS_NEW_MAIL) || (check == MX_STATUS_REOPENED))
            {
              update_index(menu, Contex2, check, idata->oldcount, &idata->cur);
            }
            OptSearchInvalid = true;
            menu->redraw = REDRAW_FULL;
            break;
          }
        }
        imap_logout_all();
        mutt_message(_("Logged out of IMAP servers"));
        OptSearchInvalid = true;
        menu->redraw = REDRAW_FULL;
        break;
#endif

      case OP_MAIN_SYNC_FOLDER:
        if (!ctx_mailbox(Contex2) || (Contex2->mailbox->msg_count == 0))
          break;

        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY))
          break;
        {
          int ovc = Contex2->mailbox->vcount;
          int oc = Contex2->mailbox->msg_count;
          struct Email *e = NULL;

          /* don't attempt to move the cursor if there are no visible messages in the current limit */
          if (menu->current < Contex2->mailbox->vcount)
          {
            /* threads may be reordered, so figure out what header the cursor
             * should be on. */
            int newidx = menu->current;
            if (!idata->cur.e)
              break;
            if (idata->cur.e->deleted)
              newidx = ci_next_undeleted(Contex2->mailbox, menu->current);
            if (newidx < 0)
              newidx = ci_previous_undeleted(Contex2->mailbox, menu->current);
            if (newidx >= 0)
              e = mutt_get_virt_email(Contex2->mailbox, newidx);
          }

          enum MxStatus check = mx_mbox_sync(Contex2->mailbox);
          if (check == MX_STATUS_OK)
          {
            if (e && (Contex2->mailbox->vcount != ovc))
            {
              for (size_t i = 0; i < Contex2->mailbox->vcount; i++)
              {
                struct Email *e2 = mutt_get_virt_email(Contex2->mailbox, i);
                if (e2 == e)
                {
                  menu->current = i;
                  break;
                }
              }
            }
            OptSearchInvalid = true;
          }
          else if ((check == MX_STATUS_NEW_MAIL) || (check == MX_STATUS_REOPENED))
          {
            update_index(menu, Contex2, check, oc, &idata->cur);
          }

          /* do a sanity check even if mx_mbox_sync failed.  */

          if ((menu->current < 0) ||
              (ctx_mailbox(Contex2) && (menu->current >= Contex2->mailbox->vcount)))
          {
            menu->current = ci_first_message(Contex2->mailbox);
          }
        }

        /* check for a fatal error, or all messages deleted */
        if (ctx_mailbox(Contex2) && mutt_buffer_is_empty(&Contex2->mailbox->pathbuf))
          ctx_free(&Contex2);

        /* if we were in the pager, redisplay the message */
        if (idata->in_pager)
        {
          op = OP_DISPLAY_MESSAGE;
          continue;
        }
        else
          menu->redraw = REDRAW_FULL;
        break;

      case OP_MAIN_QUASI_DELETE:
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE))
          break;
        if (idata->tag)
        {
          struct Mailbox *m = Contex2->mailbox;
          for (size_t i = 0; i < m->msg_count; i++)
          {
            struct Email *e = m->emails[i];
            if (!e)
              break;
            if (message_is_tagged(Contex2, e))
            {
              e->quasi_deleted = true;
              m->changed = true;
            }
          }
        }
        else
        {
          if (!idata->cur.e)
            break;
          idata->cur.e->quasi_deleted = true;
          Contex2->mailbox->changed = true;
        }
        break;

#ifdef USE_NOTMUCH
      case OP_MAIN_ENTIRE_THREAD:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE))
          break;
        char buf[PATH_MAX] = { 0 };
        if (Contex2->mailbox->type != MUTT_NOTMUCH)
        {
          if (((Contex2->mailbox->type != MUTT_MH) && (Contex2->mailbox->type != MUTT_MAILDIR)) ||
              (!idata->cur.e || !idata->cur.e->env || !idata->cur.e->env->message_id))
          {
            mutt_message(_("No virtual folder and no Message-Id, aborting"));
            break;
          } // no virtual folder, but we have message-id, reconstruct thread on-the-fly
          strncpy(buf, "id:", sizeof(buf));
          int msg_id_offset = 0;
          if ((idata->cur.e->env->message_id)[0] == '<')
            msg_id_offset = 1;
          mutt_str_cat(buf, sizeof(buf), (idata->cur.e->env->message_id) + msg_id_offset);
          if (buf[strlen(buf) - 1] == '>')
            buf[strlen(buf) - 1] = '\0';

          change_folder_notmuch(menu, buf, sizeof(buf), &idata->oldcount, &idata->cur, false);

          // If notmuch doesn't contain the message, we're left in an empty
          // vfolder. No messages are found, but nm_read_entire_thread assumes
          // a valid message-id and will throw a segfault.
          //
          // To prevent that, stay in the empty vfolder and print an error.
          if (Contex2->mailbox->msg_count == 0)
          {
            mutt_error(_("failed to find message in notmuch database. try "
                         "running 'notmuch new'."));
            break;
          }
        }
        idata->oldcount = Contex2->mailbox->msg_count;
        struct Email *e_oldcur = mutt_get_virt_email(Contex2->mailbox, menu->current);
        if (nm_read_entire_thread(Contex2->mailbox, e_oldcur) < 0)
        {
          mutt_message(_("Failed to read thread, aborting"));
          break;
        }
        if (idata->oldcount < Contex2->mailbox->msg_count)
        {
          /* nm_read_entire_thread() triggers mutt_sort_headers() if necessary */
          menu->current = e_oldcur->vnum;
          menu->redraw = REDRAW_STATUS | REDRAW_INDEX;

          if (e_oldcur->collapsed || Contex2->collapsed)
          {
            menu->current = mutt_uncollapse_thread(e_oldcur);
            mutt_set_vnum(Contex2->mailbox);
          }
        }
        if (idata->in_pager)
        {
          op = OP_DISPLAY_MESSAGE;
          continue;
        }
        break;
      }
#endif

      case OP_MAIN_MODIFY_TAGS:
      case OP_MAIN_MODIFY_TAGS_THEN_HIDE:
      {
        if (!ctx_mailbox(Contex2))
          break;
        struct Mailbox *m = Contex2->mailbox;
        if (!mx_tags_is_supported(m))
        {
          mutt_message(_("Folder doesn't support tagging, aborting"));
          break;
        }
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY))
          break;
        if (!idata->cur.e)
          break;
        char *tags = NULL;
        if (!idata->tag)
          tags = driver_tags_get_with_hidden(&idata->cur.e->tags);
        char buf[PATH_MAX] = { 0 };
        int rc = mx_tags_edit(m, tags, buf, sizeof(buf));
        FREE(&tags);
        if (rc < 0)
          break;
        else if (rc == 0)
        {
          mutt_message(_("No tag specified, aborting"));
          break;
        }

        if (idata->tag)
        {
          struct Progress progress;

          if (m->verbose)
          {
            mutt_progress_init(&progress, _("Update tags..."),
                               MUTT_PROGRESS_WRITE, m->msg_tagged);
          }

#ifdef USE_NOTMUCH
          if (m->type == MUTT_NOTMUCH)
            nm_db_longrun_init(m, true);
#endif
          for (int px = 0, i = 0; i < m->msg_count; i++)
          {
            struct Email *e = m->emails[i];
            if (!e)
              break;
            if (!message_is_tagged(Contex2, e))
              continue;

            if (m->verbose)
              mutt_progress_update(&progress, ++px, -1);
            mx_tags_commit(m, e, buf);
            if (op == OP_MAIN_MODIFY_TAGS_THEN_HIDE)
            {
              bool still_queried = false;
#ifdef USE_NOTMUCH
              if (m->type == MUTT_NOTMUCH)
                still_queried = nm_message_is_still_queried(m, e);
#endif
              e->quasi_deleted = !still_queried;
              m->changed = true;
            }
          }
#ifdef USE_NOTMUCH
          if (m->type == MUTT_NOTMUCH)
            nm_db_longrun_done(m);
#endif
          menu->redraw = REDRAW_STATUS | REDRAW_INDEX;
        }
        else
        {
          if (mx_tags_commit(m, idata->cur.e, buf))
          {
            mutt_message(_("Failed to modify tags, aborting"));
            break;
          }
          if (op == OP_MAIN_MODIFY_TAGS_THEN_HIDE)
          {
            bool still_queried = false;
#ifdef USE_NOTMUCH
            if (m->type == MUTT_NOTMUCH)
              still_queried = nm_message_is_still_queried(m, idata->cur.e);
#endif
            idata->cur.e->quasi_deleted = !still_queried;
            m->changed = true;
          }
          if (idata->in_pager)
          {
            op = OP_DISPLAY_MESSAGE;
            continue;
          }
          const bool c_resolve = cs_subset_bool(NeoMutt->sub, "resolve");
          if (c_resolve)
          {
            menu->current = ci_next_undeleted(Contex2->mailbox, menu->current);
            if (menu->current == -1)
            {
              menu->current = menu->oldcurrent;
              menu->redraw = REDRAW_CURRENT;
            }
            else
              menu->redraw = REDRAW_MOTION_RESYNC;
          }
          else
            menu->redraw = REDRAW_CURRENT;
        }
        menu->redraw |= REDRAW_STATUS;
        break;
      }

      case OP_CHECK_STATS:
        mutt_check_stats(ctx_mailbox(Contex2));
        break;

#ifdef USE_NOTMUCH
      case OP_MAIN_VFOLDER_FROM_QUERY:
      case OP_MAIN_VFOLDER_FROM_QUERY_READONLY:
      {
        char buf[PATH_MAX] = { 0 };
        if ((mutt_get_field("Query: ", buf, sizeof(buf), MUTT_NM_QUERY, false, NULL, NULL) != 0) ||
            (buf[0] == '\0'))
        {
          mutt_message(_("No query, aborting"));
          break;
        }

        // Keep copy of user's query to name the mailbox
        char *query_unencoded = mutt_str_dup(buf);

        struct Mailbox *m_query = change_folder_notmuch(
            menu, buf, sizeof(buf), &idata->oldcount, &idata->cur,
            (op == OP_MAIN_VFOLDER_FROM_QUERY_READONLY));
        if (m_query)
        {
          m_query->name = query_unencoded;
          query_unencoded = NULL;
        }
        else
        {
          FREE(&query_unencoded);
        }

        break;
      }

      case OP_MAIN_WINDOWED_VFOLDER_BACKWARD:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX))
          break;
        const short c_nm_query_window_duration =
            cs_subset_number(NeoMutt->sub, "nm_query_window_duration");
        if (c_nm_query_window_duration <= 0)
        {
          mutt_message(_("Windowed queries disabled"));
          break;
        }
        const char *c_nm_query_window_current_search =
            cs_subset_string(NeoMutt->sub, "nm_query_window_current_search");
        if (!c_nm_query_window_current_search)
        {
          mutt_message(_("No notmuch vfolder currently loaded"));
          break;
        }
        nm_query_window_backward();
        char buf[PATH_MAX] = { 0 };
        mutt_str_copy(buf, c_nm_query_window_current_search, sizeof(buf));
        change_folder_notmuch(menu, buf, sizeof(buf), &idata->oldcount, &idata->cur, false);
        break;
      }

      case OP_MAIN_WINDOWED_VFOLDER_FORWARD:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX))
          break;
        const short c_nm_query_window_duration =
            cs_subset_number(NeoMutt->sub, "nm_query_window_duration");
        if (c_nm_query_window_duration <= 0)
        {
          mutt_message(_("Windowed queries disabled"));
          break;
        }
        const char *c_nm_query_window_current_search =
            cs_subset_string(NeoMutt->sub, "nm_query_window_current_search");
        if (!c_nm_query_window_current_search)
        {
          mutt_message(_("No notmuch vfolder currently loaded"));
          break;
        }
        nm_query_window_forward();
        char buf[PATH_MAX] = { 0 };
        mutt_str_copy(buf, c_nm_query_window_current_search, sizeof(buf));
        change_folder_notmuch(menu, buf, sizeof(buf), &idata->oldcount, &idata->cur, false);
        break;
      }
#endif

#ifdef USE_SIDEBAR
      case OP_SIDEBAR_OPEN:
      {
        struct MuttWindow *win_sidebar = mutt_window_find(dlg, WT_SIDEBAR);
        change_folder_mailbox(menu, sb_get_highlight(win_sidebar),
                              &idata->oldcount, &idata->cur, false);
        break;
      }
#endif

      case OP_MAIN_NEXT_UNREAD_MAILBOX:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX))
          break;

        struct Mailbox *m = Contex2->mailbox;

        struct Buffer *folderbuf = mutt_buffer_pool_get();
        mutt_buffer_strcpy(folderbuf, mailbox_path(m));
        m = mutt_mailbox_next(m, folderbuf);
        mutt_buffer_pool_release(&folderbuf);

        if (!m)
        {
          mutt_error(_("No mailboxes have new mail"));
          break;
        }

        change_folder_mailbox(menu, m, &idata->oldcount, &idata->cur, false);
        break;
      }

      case OP_MAIN_CHANGE_FOLDER:
      case OP_MAIN_CHANGE_FOLDER_READONLY:
#ifdef USE_NOTMUCH
      case OP_MAIN_CHANGE_VFOLDER: // now an alias for OP_MAIN_CHANGE_FOLDER
#endif
      {
        bool pager_return = true; /* return to display message in pager */
        struct Buffer *folderbuf = mutt_buffer_pool_get();
        mutt_buffer_alloc(folderbuf, PATH_MAX);

        char *cp = NULL;
        bool read_only;
        const bool c_read_only = cs_subset_bool(NeoMutt->sub, "read_only");
        if (idata->attach_msg || c_read_only || (op == OP_MAIN_CHANGE_FOLDER_READONLY))
        {
          cp = _("Open mailbox in read-only mode");
          read_only = true;
        }
        else
        {
          cp = _("Open mailbox");
          read_only = false;
        }

        const bool c_change_folder_next =
            cs_subset_bool(NeoMutt->sub, "change_folder_next");
        if (c_change_folder_next && ctx_mailbox(Contex2) &&
            !mutt_buffer_is_empty(&Contex2->mailbox->pathbuf))
        {
          mutt_buffer_strcpy(folderbuf, mailbox_path(Contex2->mailbox));
          mutt_buffer_pretty_mailbox(folderbuf);
        }
        /* By default, fill buf with the next mailbox that contains unread mail */
        mutt_mailbox_next(Contex2 ? Contex2->mailbox : NULL, folderbuf);

        if (mutt_buffer_enter_fname(cp, folderbuf, true, ctx_mailbox(Contex2),
                                    false, NULL, NULL, MUTT_SEL_NO_FLAGS) == -1)
          goto changefoldercleanup;

        /* Selected directory is okay, let's save it. */
        mutt_browser_select_dir(mutt_buffer_string(folderbuf));

        if (mutt_buffer_is_empty(folderbuf))
        {
          mutt_window_clearline(MessageWindow, 0);
          goto changefoldercleanup;
        }

        struct Mailbox *m = mx_mbox_find2(mutt_buffer_string(folderbuf));
        if (m)
        {
          change_folder_mailbox(menu, m, &idata->oldcount, &idata->cur, read_only);
          pager_return = false;
        }
        else
        {
          change_folder_string(menu, folderbuf->data, folderbuf->dsize, &idata->oldcount,
                               &idata->cur, &pager_return, read_only);
        }

      changefoldercleanup:
        mutt_buffer_pool_release(&folderbuf);
        if (idata->in_pager && pager_return)
        {
          op = OP_DISPLAY_MESSAGE;
          continue;
        }
        break;
      }

#ifdef USE_NNTP
      case OP_MAIN_CHANGE_GROUP:
      case OP_MAIN_CHANGE_GROUP_READONLY:
      {
        bool pager_return = true; /* return to display message in pager */
        struct Buffer *folderbuf = mutt_buffer_pool_get();
        mutt_buffer_alloc(folderbuf, PATH_MAX);

        OptNews = false;
        bool read_only;
        char *cp = NULL;
        const bool c_read_only = cs_subset_bool(NeoMutt->sub, "read_only");
        if (idata->attach_msg || c_read_only || (op == OP_MAIN_CHANGE_GROUP_READONLY))
        {
          cp = _("Open newsgroup in read-only mode");
          read_only = true;
        }
        else
        {
          cp = _("Open newsgroup");
          read_only = false;
        }

        const bool c_change_folder_next =
            cs_subset_bool(NeoMutt->sub, "change_folder_next");
        if (c_change_folder_next && ctx_mailbox(Contex2) &&
            !mutt_buffer_is_empty(&Contex2->mailbox->pathbuf))
        {
          mutt_buffer_strcpy(folderbuf, mailbox_path(Contex2->mailbox));
          mutt_buffer_pretty_mailbox(folderbuf);
        }

        OptNews = true;
        const char *c_news_server =
            cs_subset_string(NeoMutt->sub, "news_server");
        CurrentNewsSrv = nntp_select_server(Contex2 ? Contex2->mailbox : NULL,
                                            c_news_server, false);
        if (!CurrentNewsSrv)
          goto changefoldercleanup2;

        nntp_mailbox(Contex2 ? Contex2->mailbox : NULL, folderbuf->data,
                     folderbuf->dsize);

        if (mutt_buffer_enter_fname(cp, folderbuf, true, ctx_mailbox(Contex2),
                                    false, NULL, NULL, MUTT_SEL_NO_FLAGS) == -1)
          goto changefoldercleanup2;

        /* Selected directory is okay, let's save it. */
        mutt_browser_select_dir(mutt_buffer_string(folderbuf));

        if (mutt_buffer_is_empty(folderbuf))
        {
          mutt_window_clearline(MessageWindow, 0);
          goto changefoldercleanup2;
        }

        struct Mailbox *m = mx_mbox_find2(mutt_buffer_string(folderbuf));
        if (m)
        {
          change_folder_mailbox(menu, m, &idata->oldcount, &idata->cur, read_only);
          pager_return = false;
        }
        else
        {
          change_folder_string(menu, folderbuf->data, folderbuf->dsize, &idata->oldcount,
                               &idata->cur, &pager_return, read_only);
        }
        dlg->help_data = IndexNewsHelp;

      changefoldercleanup2:
        mutt_buffer_pool_release(&folderbuf);
        if (idata->in_pager && pager_return)
        {
          op = OP_DISPLAY_MESSAGE;
          continue;
        }
        break;
      }
#endif

      case OP_DISPLAY_MESSAGE:
      case OP_DISPLAY_HEADERS: /* don't weed the headers */
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE))
          break;
        if (!idata->cur.e)
          break;
        /* toggle the weeding of headers so that a user can press the key
         * again while reading the message.  */
        if (op == OP_DISPLAY_HEADERS)
          bool_str_toggle(NeoMutt->sub, "weed", NULL);

        OptNeedResort = false;

        if (((C_Sort & SORT_MASK) == SORT_THREADS) && idata->cur.e->collapsed)
        {
          mutt_uncollapse_thread(idata->cur.e);
          mutt_set_vnum(Contex2->mailbox);
          const bool c_uncollapse_jump =
              cs_subset_bool(NeoMutt->sub, "uncollapse_jump");
          if (c_uncollapse_jump)
            menu->current = mutt_thread_next_unread(idata->cur.e);
        }

        const bool c_pgp_auto_decode =
            cs_subset_bool(NeoMutt->sub, "pgp_auto_decode");
        if (c_pgp_auto_decode &&
            (idata->tag || !(idata->cur.e->security & PGP_TRADITIONAL_CHECKED)))
        {
          struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
          el_add_tagged(&el, Contex2, idata->cur.e, idata->tag);
          mutt_check_traditional_pgp(ctx_mailbox(Contex2), &el, &menu->redraw);
          emaillist_clear(&el);
        }
        set_current_email(&idata->cur, mutt_get_virt_email(Contex2->mailbox, menu->current));

        op = mutt_display_message(win_index, win_ibar, win_pager, win_pbar,
                                  Contex2->mailbox, idata->cur.e);
        window_set_focus(win_index);
        if (op < 0)
        {
          OptNeedResort = false;
          break;
        }

        /* This is used to redirect a single operation back here afterwards.  If
         * mutt_display_message() returns 0, then this flag and pager state will
         * be cleaned up after this switch statement. */
        idata->in_pager = true;
        menu->oldcurrent = menu->current;
        if (ctx_mailbox(Contex2))
          update_index(menu, Contex2, MX_STATUS_NEW_MAIL,
                       Contex2->mailbox->msg_count, &idata->cur);
        continue;
      }

      case OP_EXIT:
        idata->close = op;
        if ((!idata->in_pager) && idata->attach_msg)
        {
          idata->done = true;
          break;
        }

        const enum QuadOption c_quit = cs_subset_quad(NeoMutt->sub, "quit");
        if ((!idata->in_pager) &&
            (query_quadoption(c_quit, _("Exit NeoMutt without saving?")) == MUTT_YES))
        {
          if (Contex2)
          {
            mx_fastclose_mailbox(Contex2->mailbox);
            ctx_free(&Contex2);
          }
          idata->done = true;
        }
        break;

      case OP_MAIN_BREAK_THREAD:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY))
          break;
        /* L10N: CHECK_ACL */
        if (!check_acl(Contex2->mailbox, MUTT_ACL_WRITE, _("Can't break thread")))
          break;
        if (!idata->cur.e)
          break;

        if ((C_Sort & SORT_MASK) != SORT_THREADS)
          mutt_error(_("Threading is not enabled"));
        else if (!STAILQ_EMPTY(&idata->cur.e->env->in_reply_to) ||
                 !STAILQ_EMPTY(&idata->cur.e->env->references))
        {
          {
            mutt_break_thread(idata->cur.e);
            mutt_sort_headers(Contex2->mailbox, Contex2->threads, true, &Contex2->vsize);
            menu->current = idata->cur.e->vnum;
          }

          Contex2->mailbox->changed = true;
          mutt_message(_("Thread broken"));

          if (idata->in_pager)
          {
            op = OP_DISPLAY_MESSAGE;
            continue;
          }
          else
            menu->redraw |= REDRAW_INDEX;
        }
        else
        {
          mutt_error(
              _("Thread can't be broken, message is not part of a thread"));
        }
        break;
      }

      case OP_MAIN_LINK_THREADS:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY))
          break;
        /* L10N: CHECK_ACL */
        if (!check_acl(Contex2->mailbox, MUTT_ACL_WRITE, _("Can't link threads")))
          break;
        if (!idata->cur.e)
          break;

        if ((C_Sort & SORT_MASK) != SORT_THREADS)
          mutt_error(_("Threading is not enabled"));
        else if (!idata->cur.e->env->message_id)
          mutt_error(_("No Message-ID: header available to link thread"));
        else
        {
          struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
          el_add_tagged(&el, Contex2, NULL, true);

          if (mutt_link_threads(idata->cur.e, &el, Contex2->mailbox))
          {
            mutt_sort_headers(Contex2->mailbox, Contex2->threads, true, &Contex2->vsize);
            menu->current = idata->cur.e->vnum;

            Contex2->mailbox->changed = true;
            mutt_message(_("Threads linked"));
          }
          else
            mutt_error(_("No thread linked"));

          emaillist_clear(&el);
        }

        if (idata->in_pager)
        {
          op = OP_DISPLAY_MESSAGE;
          continue;
        }
        else
          menu->redraw |= REDRAW_STATUS | REDRAW_INDEX;

        break;
      }

      case OP_EDIT_TYPE:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_ATTACH))
          break;
        if (!idata->cur.e)
          break;
        mutt_edit_content_type(idata->cur.e, idata->cur.e->body, NULL);
        /* if we were in the pager, redisplay the message */
        if (idata->in_pager)
        {
          op = OP_DISPLAY_MESSAGE;
          continue;
        }
        else
          menu->redraw = REDRAW_CURRENT;
        break;
      }

      case OP_MAIN_NEXT_UNDELETED:
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE))
          break;
        if (menu->current >= (Contex2->mailbox->vcount - 1))
        {
          if (!idata->in_pager)
            mutt_message(_("You are on the last message"));
          break;
        }
        menu->current = ci_next_undeleted(Contex2->mailbox, menu->current);
        if (menu->current == -1)
        {
          menu->current = menu->oldcurrent;
          if (!idata->in_pager)
            mutt_error(_("No undeleted messages"));
        }
        else if (idata->in_pager)
        {
          op = OP_DISPLAY_MESSAGE;
          continue;
        }
        else
          menu->redraw = REDRAW_MOTION;
        break;

      case OP_NEXT_ENTRY:
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE))
          break;
        if (menu->current >= (Contex2->mailbox->vcount - 1))
        {
          if (!idata->in_pager)
            mutt_message(_("You are on the last message"));
          break;
        }
        menu->current++;
        if (idata->in_pager)
        {
          op = OP_DISPLAY_MESSAGE;
          continue;
        }
        else
          menu->redraw = REDRAW_MOTION;
        break;

      case OP_MAIN_PREV_UNDELETED:
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE))
          break;
        if (menu->current < 1)
        {
          mutt_message(_("You are on the first message"));
          break;
        }
        menu->current = ci_previous_undeleted(Contex2->mailbox, menu->current);
        if (menu->current == -1)
        {
          menu->current = menu->oldcurrent;
          if (!idata->in_pager)
            mutt_error(_("No undeleted messages"));
        }
        else if (idata->in_pager)
        {
          op = OP_DISPLAY_MESSAGE;
          continue;
        }
        else
          menu->redraw = REDRAW_MOTION;
        break;

      case OP_PREV_ENTRY:
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE))
          break;
        if (menu->current < 1)
        {
          if (!idata->in_pager)
            mutt_message(_("You are on the first message"));
          break;
        }
        menu->current--;
        if (idata->in_pager)
        {
          op = OP_DISPLAY_MESSAGE;
          continue;
        }
        else
          menu->redraw = REDRAW_MOTION;
        break;

      case OP_DECRYPT_COPY:
      case OP_DECRYPT_SAVE:
        if (!WithCrypto)
          break;
      /* fallthrough */
      case OP_COPY_MESSAGE:
      case OP_SAVE:
      case OP_DECODE_COPY:
      case OP_DECODE_SAVE:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE))
          break;
        struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
        el_add_tagged(&el, Contex2, idata->cur.e, idata->tag);

        const enum MessageSaveOpt save_opt =
            ((op == OP_SAVE) || (op == OP_DECODE_SAVE) || (op == OP_DECRYPT_SAVE)) ?
                SAVE_MOVE :
                SAVE_COPY;

        enum MessageTransformOpt transform_opt =
            ((op == OP_DECODE_SAVE) || (op == OP_DECODE_COPY)) ? TRANSFORM_DECODE :
            ((op == OP_DECRYPT_SAVE) || (op == OP_DECRYPT_COPY)) ? TRANSFORM_DECRYPT :
                                                                   TRANSFORM_NONE;

        const int rc = mutt_save_message(Contex2->mailbox, &el, save_opt, transform_opt);
        if ((rc == 0) && (save_opt == SAVE_MOVE))
        {
          menu->redraw |= REDRAW_STATUS;
          const bool c_resolve = cs_subset_bool(NeoMutt->sub, "resolve");
          if (idata->tag)
            menu->redraw |= REDRAW_INDEX;
          else if (c_resolve)
          {
            menu->current = ci_next_undeleted(Contex2->mailbox, menu->current);
            if (menu->current == -1)
            {
              menu->current = menu->oldcurrent;
              menu->redraw |= REDRAW_CURRENT;
            }
            else
              menu->redraw |= REDRAW_MOTION_RESYNC;
          }
          else
            menu->redraw |= REDRAW_CURRENT;
        }
        emaillist_clear(&el);
        break;
      }

      case OP_MAIN_NEXT_NEW:
      case OP_MAIN_NEXT_UNREAD:
      case OP_MAIN_PREV_NEW:
      case OP_MAIN_PREV_UNREAD:
      case OP_MAIN_NEXT_NEW_THEN_UNREAD:
      case OP_MAIN_PREV_NEW_THEN_UNREAD:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE))
          break;

        int first_unread = -1;
        int first_new = -1;

        const int saved_current = menu->current;
        int mcur = menu->current;
        menu->current = -1;
        for (size_t i = 0; i != Contex2->mailbox->vcount; i++)
        {
          if ((op == OP_MAIN_NEXT_NEW) || (op == OP_MAIN_NEXT_UNREAD) ||
              (op == OP_MAIN_NEXT_NEW_THEN_UNREAD))
          {
            mcur++;
            if (mcur > (Contex2->mailbox->vcount - 1))
            {
              mcur = 0;
            }
          }
          else
          {
            mcur--;
            if (mcur < 0)
            {
              mcur = Contex2->mailbox->vcount - 1;
            }
          }

          struct Email *e = mutt_get_virt_email(Contex2->mailbox, mcur);
          if (!e)
            break;
          if (e->collapsed && ((C_Sort & SORT_MASK) == SORT_THREADS))
          {
            int unread = mutt_thread_contains_unread(e);
            if ((unread != 0) && (first_unread == -1))
              first_unread = mcur;
            if ((unread == 1) && (first_new == -1))
              first_new = mcur;
          }
          else if (!e->deleted && !e->read)
          {
            if (first_unread == -1)
              first_unread = mcur;
            if (!e->old && (first_new == -1))
              first_new = mcur;
          }

          if (((op == OP_MAIN_NEXT_UNREAD) || (op == OP_MAIN_PREV_UNREAD)) &&
              (first_unread != -1))
            break;
          if (((op == OP_MAIN_NEXT_NEW) || (op == OP_MAIN_PREV_NEW) ||
               (op == OP_MAIN_NEXT_NEW_THEN_UNREAD) || (op == OP_MAIN_PREV_NEW_THEN_UNREAD)) &&
              (first_new != -1))
          {
            break;
          }
        }
        if (((op == OP_MAIN_NEXT_NEW) || (op == OP_MAIN_PREV_NEW) ||
             (op == OP_MAIN_NEXT_NEW_THEN_UNREAD) || (op == OP_MAIN_PREV_NEW_THEN_UNREAD)) &&
            (first_new != -1))
        {
          menu->current = first_new;
        }
        else if (((op == OP_MAIN_NEXT_UNREAD) || (op == OP_MAIN_PREV_UNREAD) ||
                  (op == OP_MAIN_NEXT_NEW_THEN_UNREAD) || (op == OP_MAIN_PREV_NEW_THEN_UNREAD)) &&
                 (first_unread != -1))
        {
          menu->current = first_unread;
        }

        if (menu->current == -1)
        {
          menu->current = menu->oldcurrent;
          if ((op == OP_MAIN_NEXT_NEW) || (op == OP_MAIN_PREV_NEW))
          {
            if (ctx_has_limit(Contex2))
              mutt_error(_("No new messages in this limited view"));
            else
              mutt_error(_("No new messages"));
          }
          else
          {
            if (ctx_has_limit(Contex2))
              mutt_error(_("No unread messages in this limited view"));
            else
              mutt_error(_("No unread messages"));
          }
          break;
        }

        if ((op == OP_MAIN_NEXT_NEW) || (op == OP_MAIN_NEXT_UNREAD) ||
            (op == OP_MAIN_NEXT_NEW_THEN_UNREAD))
        {
          if (saved_current > menu->current)
          {
            mutt_message(_("Search wrapped to top"));
          }
        }
        else if (saved_current < menu->current)
        {
          mutt_message(_("Search wrapped to bottom"));
        }

        if (idata->in_pager)
        {
          op = OP_DISPLAY_MESSAGE;
          continue;
        }
        else
          menu->redraw = REDRAW_MOTION;
        break;
      }
      case OP_FLAG_MESSAGE:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY))
          break;
        /* L10N: CHECK_ACL */
        if (!check_acl(Contex2->mailbox, MUTT_ACL_WRITE, _("Can't flag message")))
          break;

        struct Mailbox *m = Contex2->mailbox;
        if (idata->tag)
        {
          for (size_t i = 0; i < m->msg_count; i++)
          {
            struct Email *e = m->emails[i];
            if (!e)
              break;
            if (message_is_tagged(Contex2, e))
              mutt_set_flag(m, e, MUTT_FLAG, !e->flagged);
          }

          menu->redraw |= REDRAW_INDEX;
        }
        else
        {
          if (!idata->cur.e)
            break;
          mutt_set_flag(m, idata->cur.e, MUTT_FLAG, !idata->cur.e->flagged);
          const bool c_resolve = cs_subset_bool(NeoMutt->sub, "resolve");
          if (c_resolve)
          {
            menu->current = ci_next_undeleted(Contex2->mailbox, menu->current);
            if (menu->current == -1)
            {
              menu->current = menu->oldcurrent;
              menu->redraw |= REDRAW_CURRENT;
            }
            else
              menu->redraw |= REDRAW_MOTION_RESYNC;
          }
          else
            menu->redraw |= REDRAW_CURRENT;
        }
        menu->redraw |= REDRAW_STATUS;
        break;
      }

      case OP_TOGGLE_NEW:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY))
          break;
        /* L10N: CHECK_ACL */
        if (!check_acl(Contex2->mailbox, MUTT_ACL_SEEN, _("Can't toggle new")))
          break;

        struct Mailbox *m = Contex2->mailbox;
        if (idata->tag)
        {
          for (size_t i = 0; i < m->msg_count; i++)
          {
            struct Email *e = m->emails[i];
            if (!e)
              break;
            if (!message_is_tagged(Contex2, e))
              continue;

            if (e->read || e->old)
              mutt_set_flag(m, e, MUTT_NEW, true);
            else
              mutt_set_flag(m, e, MUTT_READ, true);
          }
          menu->redraw |= REDRAW_STATUS | REDRAW_INDEX;
        }
        else
        {
          if (!idata->cur.e)
            break;
          if (idata->cur.e->read || idata->cur.e->old)
            mutt_set_flag(m, idata->cur.e, MUTT_NEW, true);
          else
            mutt_set_flag(m, idata->cur.e, MUTT_READ, true);

          const bool c_resolve = cs_subset_bool(NeoMutt->sub, "resolve");
          if (c_resolve)
          {
            menu->current = ci_next_undeleted(Contex2->mailbox, menu->current);
            if (menu->current == -1)
            {
              menu->current = menu->oldcurrent;
              menu->redraw |= REDRAW_CURRENT;
            }
            else
              menu->redraw |= REDRAW_MOTION_RESYNC;
          }
          else
            menu->redraw |= REDRAW_CURRENT;
          menu->redraw |= REDRAW_STATUS;
        }
        break;
      }

      case OP_TOGGLE_WRITE:
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX))
          break;
        if (mx_toggle_write(Contex2->mailbox) == 0)
        {
          if (idata->in_pager)
          {
            op = OP_DISPLAY_MESSAGE;
            continue;
          }
          else
            menu->redraw |= REDRAW_STATUS;
        }
        break;

      case OP_MAIN_NEXT_THREAD:
      case OP_MAIN_NEXT_SUBTHREAD:
      case OP_MAIN_PREV_THREAD:
      case OP_MAIN_PREV_SUBTHREAD:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE))
          break;

        switch (op)
        {
          case OP_MAIN_NEXT_THREAD:
            menu->current = mutt_next_thread(idata->cur.e);
            break;

          case OP_MAIN_NEXT_SUBTHREAD:
            menu->current = mutt_next_subthread(idata->cur.e);
            break;

          case OP_MAIN_PREV_THREAD:
            menu->current = mutt_previous_thread(idata->cur.e);
            break;

          case OP_MAIN_PREV_SUBTHREAD:
            menu->current = mutt_previous_subthread(idata->cur.e);
            break;
        }

        if (menu->current < 0)
        {
          menu->current = menu->oldcurrent;
          if ((op == OP_MAIN_NEXT_THREAD) || (op == OP_MAIN_NEXT_SUBTHREAD))
            mutt_error(_("No more threads"));
          else
            mutt_error(_("You are on the first thread"));
        }
        else if (idata->in_pager)
        {
          op = OP_DISPLAY_MESSAGE;
          continue;
        }
        else
          menu->redraw = REDRAW_MOTION;
        break;
      }

      case OP_MAIN_ROOT_MESSAGE:
      case OP_MAIN_PARENT_MESSAGE:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE))
          break;

        menu->current = mutt_parent_message(idata->cur.e, op == OP_MAIN_ROOT_MESSAGE);
        if (menu->current < 0)
        {
          menu->current = menu->oldcurrent;
        }
        else if (idata->in_pager)
        {
          op = OP_DISPLAY_MESSAGE;
          continue;
        }
        else
          menu->redraw = REDRAW_MOTION;
        break;
      }

      case OP_MAIN_SET_FLAG:
      case OP_MAIN_CLEAR_FLAG:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY))
          break;
        /* check_acl(MUTT_ACL_WRITE); */

        struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
        el_add_tagged(&el, Contex2, idata->cur.e, idata->tag);

        if (mutt_change_flag(Contex2->mailbox, &el, (op == OP_MAIN_SET_FLAG)) == 0)
        {
          menu->redraw |= REDRAW_STATUS;
          const bool c_resolve = cs_subset_bool(NeoMutt->sub, "resolve");
          if (idata->tag)
            menu->redraw |= REDRAW_INDEX;
          else if (c_resolve)
          {
            menu->current = ci_next_undeleted(Contex2->mailbox, menu->current);
            if (menu->current == -1)
            {
              menu->current = menu->oldcurrent;
              menu->redraw |= REDRAW_CURRENT;
            }
            else
              menu->redraw |= REDRAW_MOTION_RESYNC;
          }
          else
            menu->redraw |= REDRAW_CURRENT;
        }
        emaillist_clear(&el);
        break;
      }

      case OP_MAIN_COLLAPSE_THREAD:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE))
          break;

        if ((C_Sort & SORT_MASK) != SORT_THREADS)
        {
          mutt_error(_("Threading is not enabled"));
          break;
        }

        if (!idata->cur.e)
          break;

        if (idata->cur.e->collapsed)
        {
          menu->current = mutt_uncollapse_thread(idata->cur.e);
          mutt_set_vnum(Contex2->mailbox);
          const bool c_uncollapse_jump =
              cs_subset_bool(NeoMutt->sub, "uncollapse_jump");
          if (c_uncollapse_jump)
            menu->current = mutt_thread_next_unread(idata->cur.e);
        }
        else if (mutt_thread_can_collapse(idata->cur.e))
        {
          menu->current = mutt_collapse_thread(idata->cur.e);
          mutt_set_vnum(Contex2->mailbox);
        }
        else
        {
          mutt_error(_("Thread contains unread or flagged messages"));
          break;
        }

        menu->redraw = REDRAW_INDEX | REDRAW_STATUS;

        break;
      }

      case OP_MAIN_COLLAPSE_ALL:
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX))
          break;

        if ((C_Sort & SORT_MASK) != SORT_THREADS)
        {
          mutt_error(_("Threading is not enabled"));
          break;
        }
        collapse_all(Contex2, menu, 1);
        break;

        /* --------------------------------------------------------------------
         * These functions are invoked directly from the internal-pager
         */

      case OP_BOUNCE_MESSAGE:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_ATTACH))
          break;
        struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
        el_add_tagged(&el, Contex2, idata->cur.e, idata->tag);
        ci_bounce_message(Contex2->mailbox, &el);
        emaillist_clear(&el);
        break;
      }

      case OP_CREATE_ALIAS:
      {
        struct AddressList *al = NULL;
        if (idata->cur.e && idata->cur.e->env)
          al = mutt_get_address(idata->cur.e->env, NULL);
        alias_create(al, NeoMutt->sub);
        menu->redraw |= REDRAW_CURRENT;
        break;
      }

      case OP_QUERY:
        if (!prereq(Contex2, menu, CHECK_ATTACH))
          break;
        query_index(NeoMutt->sub);
        break;

      case OP_PURGE_MESSAGE:
      case OP_DELETE:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY))
          break;
        /* L10N: CHECK_ACL */
        if (!check_acl(Contex2->mailbox, MUTT_ACL_DELETE, _("Can't delete message")))
          break;

        struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
        el_add_tagged(&el, Contex2, idata->cur.e, idata->tag);

        mutt_emails_set_flag(Contex2->mailbox, &el, MUTT_DELETE, 1);
        mutt_emails_set_flag(Contex2->mailbox, &el, MUTT_PURGE, (op == OP_PURGE_MESSAGE));
        const bool c_delete_untag =
            cs_subset_bool(NeoMutt->sub, "delete_untag");
        if (c_delete_untag)
          mutt_emails_set_flag(Contex2->mailbox, &el, MUTT_TAG, 0);
        emaillist_clear(&el);

        if (idata->tag)
        {
          menu->redraw |= REDRAW_INDEX;
        }
        else
        {
          const bool c_resolve = cs_subset_bool(NeoMutt->sub, "resolve");
          if (c_resolve)
          {
            menu->current = ci_next_undeleted(Contex2->mailbox, menu->current);
            if (menu->current == -1)
            {
              menu->current = menu->oldcurrent;
              menu->redraw |= REDRAW_CURRENT;
            }
            else if (idata->in_pager)
            {
              op = OP_DISPLAY_MESSAGE;
              continue;
            }
            else
              menu->redraw |= REDRAW_MOTION_RESYNC;
          }
          else
            menu->redraw |= REDRAW_CURRENT;
        }
        menu->redraw |= REDRAW_STATUS;
        break;
      }

      case OP_DELETE_THREAD:
      case OP_DELETE_SUBTHREAD:
      case OP_PURGE_THREAD:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY))
          break;
        /* L10N: CHECK_ACL */
        /* L10N: Due to the implementation details we do not know whether we
           delete zero, 1, 12, ... messages. So in English we use
           "messages". Your language might have other means to express this. */
        if (!check_acl(Contex2->mailbox, MUTT_ACL_DELETE, _("Can't delete messages")))
          break;
        if (!idata->cur.e)
          break;

        int subthread = (op == OP_DELETE_SUBTHREAD);
        int rc = mutt_thread_set_flag(ctx_mailbox(Contex2), idata->cur.e,
                                      MUTT_DELETE, true, subthread);
        if (rc == -1)
          break;
        if (op == OP_PURGE_THREAD)
        {
          rc = mutt_thread_set_flag(ctx_mailbox(Contex2), idata->cur.e,
                                    MUTT_PURGE, true, subthread);
          if (rc == -1)
            break;
        }

        const bool c_delete_untag =
            cs_subset_bool(NeoMutt->sub, "delete_untag");
        if (c_delete_untag)
          mutt_thread_set_flag(ctx_mailbox(Contex2), idata->cur.e, MUTT_TAG, false, subthread);
        const bool c_resolve = cs_subset_bool(NeoMutt->sub, "resolve");
        if (c_resolve)
        {
          menu->current = ci_next_undeleted(Contex2->mailbox, menu->current);
          if (menu->current == -1)
            menu->current = menu->oldcurrent;
        }
        menu->redraw |= REDRAW_INDEX | REDRAW_STATUS;
        break;
      }

#ifdef USE_NNTP
      case OP_CATCHUP:
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY | CHECK_ATTACH))
          break;
        if (Contex2 && (Contex2->mailbox->type == MUTT_NNTP))
        {
          struct NntpMboxData *mdata = Contex2->mailbox->mdata;
          if (mutt_newsgroup_catchup(Contex2->mailbox, mdata->adata, mdata->group))
            menu->redraw = REDRAW_INDEX | REDRAW_STATUS;
        }
        break;
#endif

      case OP_DISPLAY_ADDRESS:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE))
          break;
        if (!idata->cur.e)
          break;
        mutt_display_address(idata->cur.e->env);
        break;
      }

      case OP_ENTER_COMMAND:
        mutt_enter_command();
        window_set_focus(win_index);
        if (Contex2)
          mutt_check_rescore(Contex2->mailbox);
        menu->redraw = REDRAW_FULL;
        break;

      case OP_EDIT_OR_VIEW_RAW_MESSAGE:
      case OP_EDIT_RAW_MESSAGE:
      case OP_VIEW_RAW_MESSAGE:
      {
        /* TODO split this into 3 cases? */
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_ATTACH))
          break;
        bool edit;
        if (op == OP_EDIT_RAW_MESSAGE)
        {
          if (!prereq(Contex2, menu, CHECK_READONLY))
            break;
          /* L10N: CHECK_ACL */
          if (!check_acl(Contex2->mailbox, MUTT_ACL_INSERT, _("Can't edit message")))
            break;
          edit = true;
        }
        else if (op == OP_EDIT_OR_VIEW_RAW_MESSAGE)
          edit = !Contex2->mailbox->readonly && (Contex2->mailbox->rights & MUTT_ACL_INSERT);
        else
          edit = false;

        if (!idata->cur.e)
          break;
        const bool c_pgp_auto_decode =
            cs_subset_bool(NeoMutt->sub, "pgp_auto_decode");
        if (c_pgp_auto_decode &&
            (idata->tag || !(idata->cur.e->security & PGP_TRADITIONAL_CHECKED)))
        {
          struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
          el_add_tagged(&el, Contex2, idata->cur.e, idata->tag);
          mutt_check_traditional_pgp(ctx_mailbox(Contex2), &el, &menu->redraw);
          emaillist_clear(&el);
        }
        struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
        el_add_tagged(&el, Contex2, idata->cur.e, idata->tag);
        mutt_ev_message(Contex2->mailbox, &el, edit ? EVM_EDIT : EVM_VIEW);
        emaillist_clear(&el);
        menu->redraw = REDRAW_FULL;

        break;
      }

      case OP_FORWARD_MESSAGE:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_ATTACH))
          break;
        if (!idata->cur.e)
          break;
        struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
        el_add_tagged(&el, Contex2, idata->cur.e, idata->tag);
        const bool c_pgp_auto_decode =
            cs_subset_bool(NeoMutt->sub, "pgp_auto_decode");
        if (c_pgp_auto_decode &&
            (idata->tag || !(idata->cur.e->security & PGP_TRADITIONAL_CHECKED)))
        {
          mutt_check_traditional_pgp(ctx_mailbox(Contex2), &el, &menu->redraw);
        }
        mutt_send_message(SEND_FORWARD, NULL, NULL, Contex2, &el, NeoMutt->sub);
        emaillist_clear(&el);
        menu->redraw = REDRAW_FULL;
        break;
      }

      case OP_FORGET_PASSPHRASE:
        crypt_forget_passphrase();
        break;

      case OP_GROUP_REPLY:
      case OP_GROUP_CHAT_REPLY:
      {
        SendFlags replyflags = SEND_REPLY;
        if (op == OP_GROUP_REPLY)
          replyflags |= SEND_GROUP_REPLY;
        else
          replyflags |= SEND_GROUP_CHAT_REPLY;
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_ATTACH))
          break;
        if (!idata->cur.e)
          break;
        struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
        el_add_tagged(&el, Contex2, idata->cur.e, idata->tag);
        const bool c_pgp_auto_decode =
            cs_subset_bool(NeoMutt->sub, "pgp_auto_decode");
        if (c_pgp_auto_decode &&
            (idata->tag || !(idata->cur.e->security & PGP_TRADITIONAL_CHECKED)))
        {
          mutt_check_traditional_pgp(ctx_mailbox(Contex2), &el, &menu->redraw);
        }
        mutt_send_message(replyflags, NULL, NULL, Contex2, &el, NeoMutt->sub);
        emaillist_clear(&el);
        menu->redraw = REDRAW_FULL;
        break;
      }

      case OP_EDIT_LABEL:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY))
          break;

        struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
        el_add_tagged(&el, Contex2, idata->cur.e, idata->tag);
        int num_changed = mutt_label_message(Contex2->mailbox, &el);
        emaillist_clear(&el);

        if (num_changed > 0)
        {
          Contex2->mailbox->changed = true;
          menu->redraw = REDRAW_FULL;
          /* L10N: This is displayed when the x-label on one or more
             messages is edited. */
          mutt_message(ngettext("%d label changed", "%d labels changed", num_changed),
                       num_changed);
        }
        else
        {
          /* L10N: This is displayed when editing an x-label, but no messages
             were updated.  Possibly due to canceling at the prompt or if the new
             label is the same as the old label. */
          mutt_message(_("No labels changed"));
        }
        break;
      }

      case OP_LIST_REPLY:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_ATTACH))
          break;
        if (!idata->cur.e)
          break;
        struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
        el_add_tagged(&el, Contex2, idata->cur.e, idata->tag);
        const bool c_pgp_auto_decode =
            cs_subset_bool(NeoMutt->sub, "pgp_auto_decode");
        if (c_pgp_auto_decode &&
            (idata->tag || !(idata->cur.e->security & PGP_TRADITIONAL_CHECKED)))
        {
          mutt_check_traditional_pgp(ctx_mailbox(Contex2), &el, &menu->redraw);
        }
        mutt_send_message(SEND_REPLY | SEND_LIST_REPLY, NULL, NULL, Contex2,
                          &el, NeoMutt->sub);
        emaillist_clear(&el);
        menu->redraw = REDRAW_FULL;
        break;
      }

      case OP_MAIL:
        if (!prereq(Contex2, menu, CHECK_ATTACH))
          break;
        mutt_send_message(SEND_NO_FLAGS, NULL, NULL, Contex2, NULL, NeoMutt->sub);
        menu->redraw = REDRAW_FULL;
        break;

      case OP_MAIL_KEY:
        if (!(WithCrypto & APPLICATION_PGP))
          break;
        if (!prereq(Contex2, menu, CHECK_ATTACH))
          break;
        mutt_send_message(SEND_KEY, NULL, NULL, NULL, NULL, NeoMutt->sub);
        menu->redraw = REDRAW_FULL;
        break;

      case OP_EXTRACT_KEYS:
      {
        if (!WithCrypto)
          break;
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE))
          break;
        struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
        el_add_tagged(&el, Contex2, idata->cur.e, idata->tag);
        crypt_extract_keys_from_messages(Contex2->mailbox, &el);
        emaillist_clear(&el);
        menu->redraw = REDRAW_FULL;
        break;
      }

      case OP_CHECK_TRADITIONAL:
      {
        if (!(WithCrypto & APPLICATION_PGP))
          break;
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE))
          break;
        if (!idata->cur.e)
          break;
        if (idata->tag || !(idata->cur.e->security & PGP_TRADITIONAL_CHECKED))
        {
          struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
          el_add_tagged(&el, Contex2, idata->cur.e, idata->tag);
          mutt_check_traditional_pgp(ctx_mailbox(Contex2), &el, &menu->redraw);
          emaillist_clear(&el);
        }

        if (idata->in_pager)
        {
          op = OP_DISPLAY_MESSAGE;
          continue;
        }
        break;
      }

      case OP_PIPE:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE))
          break;
        struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
        el_add_tagged(&el, Contex2, idata->cur.e, idata->tag);
        mutt_pipe_message(Contex2->mailbox, &el);
        emaillist_clear(&el);

#ifdef USE_IMAP
        /* in an IMAP folder index with imap_peek=no, piping could change
         * new or old messages status to read. Redraw what's needed.  */
        const bool c_imap_peek = cs_subset_bool(NeoMutt->sub, "imap_peek");
        if ((Contex2->mailbox->type == MUTT_IMAP) && !c_imap_peek)
        {
          menu->redraw |= (idata->tag ? REDRAW_INDEX : REDRAW_CURRENT) | REDRAW_STATUS;
        }
#endif
        break;
      }

      case OP_PRINT:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE))
          break;
        struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
        el_add_tagged(&el, Contex2, idata->cur.e, idata->tag);
        mutt_print_message(Contex2->mailbox, &el);
        emaillist_clear(&el);

#ifdef USE_IMAP
        /* in an IMAP folder index with imap_peek=no, printing could change
         * new or old messages status to read. Redraw what's needed.  */
        const bool c_imap_peek = cs_subset_bool(NeoMutt->sub, "imap_peek");
        if ((Contex2->mailbox->type == MUTT_IMAP) && !c_imap_peek)
        {
          menu->redraw |= (idata->tag ? REDRAW_INDEX : REDRAW_CURRENT) | REDRAW_STATUS;
        }
#endif
        break;
      }

      case OP_MAIN_READ_THREAD:
      case OP_MAIN_READ_SUBTHREAD:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY))
          break;
        /* L10N: CHECK_ACL */
        /* L10N: Due to the implementation details we do not know whether we
           mark zero, 1, 12, ... messages as read. So in English we use
           "messages". Your language might have other means to express this. */
        if (!check_acl(Contex2->mailbox, MUTT_ACL_SEEN, _("Can't mark messages as read")))
          break;

        int rc = mutt_thread_set_flag(ctx_mailbox(Contex2), idata->cur.e, MUTT_READ,
                                      true, (op != OP_MAIN_READ_THREAD));
        if (rc != -1)
        {
          const bool c_resolve = cs_subset_bool(NeoMutt->sub, "resolve");
          if (c_resolve)
          {
            menu->current =
                ((op == OP_MAIN_READ_THREAD) ? mutt_next_thread(idata->cur.e) :
                                               mutt_next_subthread(idata->cur.e));
            if (menu->current == -1)
            {
              menu->current = menu->oldcurrent;
            }
            else if (idata->in_pager)
            {
              op = OP_DISPLAY_MESSAGE;
              continue;
            }
          }
          menu->redraw |= REDRAW_INDEX | REDRAW_STATUS;
        }
        break;
      }

      case OP_MARK_MSG:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE))
          break;
        if (!idata->cur.e)
          break;
        if (idata->cur.e->env->message_id)
        {
          char buf2[128];

          buf2[0] = '\0';
          /* L10N: This is the prompt for <mark-message>.  Whatever they
             enter will be prefixed by $mark_macro_prefix and will become
             a macro hotkey to jump to the currently selected message. */
          if (!mutt_get_field(_("Enter macro stroke: "), buf2, sizeof(buf2),
                              MUTT_COMP_NO_FLAGS, false, NULL, NULL) &&
              buf2[0])
          {
            char str[256], macro[256];
            const char *c_mark_macro_prefix =
                cs_subset_string(NeoMutt->sub, "mark_macro_prefix");
            snprintf(str, sizeof(str), "%s%s", c_mark_macro_prefix, buf2);
            snprintf(macro, sizeof(macro), "<search>~i \"%s\"\n",
                     idata->cur.e->env->message_id);
            /* L10N: "message hotkey" is the key bindings menu description of a
               macro created by <mark-message>. */
            km_bind(str, MENU_MAIN, OP_MACRO, macro, _("message hotkey"));

            /* L10N: This is echoed after <mark-message> creates a new hotkey
               macro.  %s is the hotkey string ($mark_macro_prefix followed
               by whatever they typed at the prompt.) */
            snprintf(buf2, sizeof(buf2), _("Message bound to %s"), str);
            mutt_message(buf2);
            mutt_debug(LL_DEBUG1, "Mark: %s => %s\n", str, macro);
          }
        }
        else
        {
          /* L10N: This error is printed if <mark-message> can't find a
             Message-ID for the currently selected message in the index. */
          mutt_error(_("No message ID to macro"));
        }
        break;
      }

      case OP_RECALL_MESSAGE:
        if (!prereq(Contex2, menu, CHECK_ATTACH))
          break;
        mutt_send_message(SEND_POSTPONED, NULL, NULL, Contex2, NULL, NeoMutt->sub);
        menu->redraw = REDRAW_FULL;
        break;

      case OP_RESEND:
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_ATTACH))
          break;

        if (idata->tag)
        {
          struct Mailbox *m = Contex2->mailbox;
          for (size_t i = 0; i < m->msg_count; i++)
          {
            struct Email *e = m->emails[i];
            if (!e)
              break;
            if (message_is_tagged(Contex2, e))
              mutt_resend_message(NULL, Contex2, e, NeoMutt->sub);
          }
        }
        else
        {
          mutt_resend_message(NULL, Contex2, idata->cur.e, NeoMutt->sub);
        }

        menu->redraw = REDRAW_FULL;
        break;

#ifdef USE_NNTP
      case OP_FOLLOWUP:
      case OP_FORWARD_TO_GROUP:
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE))
          break;
        /* fallthrough */

      case OP_POST:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_ATTACH))
          break;
        if (!idata->cur.e)
          break;
        const enum QuadOption c_followup_to_poster =
            cs_subset_quad(NeoMutt->sub, "followup_to_poster");
        if ((op != OP_FOLLOWUP) || !idata->cur.e->env->followup_to ||
            !mutt_istr_equal(idata->cur.e->env->followup_to, "poster") ||
            (query_quadoption(c_followup_to_poster,
                              _("Reply by mail as poster prefers?")) != MUTT_YES))
        {
          const enum QuadOption c_post_moderated =
              cs_subset_quad(NeoMutt->sub, "post_moderated");
          if (Contex2 && (Contex2->mailbox->type == MUTT_NNTP) &&
              !((struct NntpMboxData *) Contex2->mailbox->mdata)->allowed && (query_quadoption(c_post_moderated, _("Posting to this group not allowed, may be moderated. Continue?")) != MUTT_YES))
          {
            break;
          }
          if (op == OP_POST)
            mutt_send_message(SEND_NEWS, NULL, NULL, Contex2, NULL, NeoMutt->sub);
          else
          {
            if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT))
              break;
            struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
            el_add_tagged(&el, Contex2, idata->cur.e, idata->tag);
            mutt_send_message(((op == OP_FOLLOWUP) ? SEND_REPLY : SEND_FORWARD) | SEND_NEWS,
                              NULL, NULL, Contex2, &el, NeoMutt->sub);
            emaillist_clear(&el);
          }
          menu->redraw = REDRAW_FULL;
          break;
        }
      }
#endif
      /* fallthrough */
      case OP_REPLY:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_ATTACH))
          break;
        if (!idata->cur.e)
          break;
        struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
        el_add_tagged(&el, Contex2, idata->cur.e, idata->tag);
        const bool c_pgp_auto_decode =
            cs_subset_bool(NeoMutt->sub, "pgp_auto_decode");
        if (c_pgp_auto_decode &&
            (idata->tag || !(idata->cur.e->security & PGP_TRADITIONAL_CHECKED)))
        {
          mutt_check_traditional_pgp(ctx_mailbox(Contex2), &el, &menu->redraw);
        }
        mutt_send_message(SEND_REPLY, NULL, NULL, Contex2, &el, NeoMutt->sub);
        emaillist_clear(&el);
        menu->redraw = REDRAW_FULL;
        break;
      }

      case OP_SHELL_ESCAPE:
        if (mutt_shell_escape())
        {
          mutt_mailbox_check(ctx_mailbox(Contex2), MUTT_MAILBOX_CHECK_FORCE);
        }
        break;

      case OP_TAG_THREAD:
      case OP_TAG_SUBTHREAD:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE))
          break;
        if (!idata->cur.e)
          break;

        int rc = mutt_thread_set_flag(ctx_mailbox(Contex2), idata->cur.e, MUTT_TAG,
                                      !idata->cur.e->tagged, (op != OP_TAG_THREAD));
        if (rc != -1)
        {
          const bool c_resolve = cs_subset_bool(NeoMutt->sub, "resolve");
          if (c_resolve)
          {
            if (op == OP_TAG_THREAD)
              menu->current = mutt_next_thread(idata->cur.e);
            else
              menu->current = mutt_next_subthread(idata->cur.e);

            if (menu->current == -1)
              menu->current = menu->oldcurrent;
          }
          menu->redraw |= REDRAW_INDEX | REDRAW_STATUS;
        }
        break;
      }

      case OP_UNDELETE:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY))
          break;
        /* L10N: CHECK_ACL */
        if (!check_acl(Contex2->mailbox, MUTT_ACL_DELETE, _("Can't undelete message")))
          break;

        struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
        el_add_tagged(&el, Contex2, idata->cur.e, idata->tag);

        mutt_emails_set_flag(Contex2->mailbox, &el, MUTT_DELETE, 0);
        mutt_emails_set_flag(Contex2->mailbox, &el, MUTT_PURGE, 0);
        emaillist_clear(&el);

        if (idata->tag)
        {
          menu->redraw |= REDRAW_INDEX;
        }
        else
        {
          const bool c_resolve = cs_subset_bool(NeoMutt->sub, "resolve");
          if (c_resolve && (menu->current < (Contex2->mailbox->vcount - 1)))
          {
            menu->current++;
            menu->redraw |= REDRAW_MOTION_RESYNC;
          }
          else
            menu->redraw |= REDRAW_CURRENT;
        }

        menu->redraw |= REDRAW_STATUS;
        break;
      }

      case OP_UNDELETE_THREAD:
      case OP_UNDELETE_SUBTHREAD:
      {
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY))
          break;
        /* L10N: CHECK_ACL */
        /* L10N: Due to the implementation details we do not know whether we
            undelete zero, 1, 12, ... messages. So in English we use
            "messages". Your language might have other means to express this. */
        if (!check_acl(Contex2->mailbox, MUTT_ACL_DELETE, _("Can't undelete messages")))
          break;

        int rc = mutt_thread_set_flag(ctx_mailbox(Contex2), idata->cur.e, MUTT_DELETE,
                                      false, (op != OP_UNDELETE_THREAD));
        if (rc != -1)
        {
          rc = mutt_thread_set_flag(ctx_mailbox(Contex2), idata->cur.e, MUTT_PURGE,
                                    false, (op != OP_UNDELETE_THREAD));
        }
        if (rc != -1)
        {
          const bool c_resolve = cs_subset_bool(NeoMutt->sub, "resolve");
          if (c_resolve)
          {
            if (op == OP_UNDELETE_THREAD)
              menu->current = mutt_next_thread(idata->cur.e);
            else
              menu->current = mutt_next_subthread(idata->cur.e);

            if (menu->current == -1)
              menu->current = menu->oldcurrent;
          }
          menu->redraw |= REDRAW_INDEX | REDRAW_STATUS;
        }
        break;
      }

      case OP_VERSION:
        mutt_message(mutt_make_version());
        break;

      case OP_MAILBOX_LIST:
        mutt_mailbox_list();
        break;

      case OP_VIEW_ATTACHMENTS:
        if (!prereq(Contex2, menu, CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE))
          break;
        if (!idata->cur.e)
          break;
        dlg_select_attachment(idata->cur.e);
        if (idata->cur.e->attach_del)
          Contex2->mailbox->changed = true;
        menu->redraw = REDRAW_FULL;
        break;

      case OP_END_COND:
        break;

      case OP_WHAT_KEY:
        mutt_what_key();
        break;

#ifdef USE_SIDEBAR
      case OP_SIDEBAR_FIRST:
      case OP_SIDEBAR_LAST:
      case OP_SIDEBAR_NEXT:
      case OP_SIDEBAR_NEXT_NEW:
      case OP_SIDEBAR_PAGE_DOWN:
      case OP_SIDEBAR_PAGE_UP:
      case OP_SIDEBAR_PREV:
      case OP_SIDEBAR_PREV_NEW:
      {
        struct MuttWindow *win_sidebar = mutt_window_find(dlg, WT_SIDEBAR);
        if (!win_sidebar)
          break;
        sb_change_mailbox(win_sidebar, op);
        break;
      }

      case OP_SIDEBAR_TOGGLE_VISIBLE:
        bool_str_toggle(NeoMutt->sub, "sidebar_visible", NULL);
        mutt_window_reflow(NULL);
        break;
#endif

#ifdef USE_AUTOCRYPT
      case OP_AUTOCRYPT_ACCT_MENU:
        dlg_select_autocrypt_account(ctx_mailbox(Contex2));
        break;
#endif

      default:
        if (!idata->in_pager)
          km_error_key(MENU_MAIN);
    }

#ifdef USE_NOTMUCH
    if (Contex2)
      nm_db_debug_check(Contex2->mailbox);
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
 * add_panel_index - Create the Windows for the Index panel
 * @param parent        Parent Window
 * @param status_on_top true, if the Index bar should be on top
 */
static void add_panel_index(struct MuttWindow *parent, bool status_on_top)
{
  struct MuttWindow *panel_index =
      mutt_window_new(WT_CONTAINER, MUTT_WIN_ORIENT_VERTICAL, MUTT_WIN_SIZE_MAXIMISE,
                      MUTT_WIN_SIZE_UNLIMITED, MUTT_WIN_SIZE_UNLIMITED);
  parent->focus = panel_index;
  mutt_window_add_child(parent, panel_index);

  struct MuttWindow *win_index =
      mutt_window_new(WT_INDEX, MUTT_WIN_ORIENT_VERTICAL, MUTT_WIN_SIZE_MAXIMISE,
                      MUTT_WIN_SIZE_UNLIMITED, MUTT_WIN_SIZE_UNLIMITED);
  panel_index->focus = win_index;

  struct MuttWindow *win_ibar =
      mutt_window_new(WT_INDEX_BAR, MUTT_WIN_ORIENT_VERTICAL,
                      MUTT_WIN_SIZE_FIXED, MUTT_WIN_SIZE_UNLIMITED, 1);

  struct MuttWindow *win_ibar2 = ibar_create(panel_index);

  if (status_on_top)
  {
    mutt_window_add_child(panel_index, win_ibar);
    mutt_window_add_child(panel_index, win_index);
    mutt_window_add_child(panel_index, win_ibar2);
  }
  else
  {
    mutt_window_add_child(panel_index, win_index);
    mutt_window_add_child(panel_index, win_ibar);
    mutt_window_add_child(panel_index, win_ibar2);
  }
}

/**
 * add_panel_pager - Create the Windows for the Pager panel
 * @param parent        Parent Window
 * @param status_on_top true, if the Pager bar should be on top
 */
static void add_panel_pager(struct MuttWindow *parent, bool status_on_top)
{
  struct MuttWindow *panel_pager =
      mutt_window_new(WT_CONTAINER, MUTT_WIN_ORIENT_VERTICAL, MUTT_WIN_SIZE_MAXIMISE,
                      MUTT_WIN_SIZE_UNLIMITED, MUTT_WIN_SIZE_UNLIMITED);
  panel_pager->state.visible = false; // The Pager and Pager Bar are initially hidden
  mutt_window_add_child(parent, panel_pager);

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
  add_panel_index(dlg, c_status_on_top);
  add_panel_pager(dlg, c_status_on_top);

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
