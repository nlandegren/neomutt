/**
 * @file
 * Index functions
 *
 * @authors
 * Copyright (C) 2021 Richard Russon <rich@flatcap.org>
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
 * @page index_functions Index functions
 *
 * Index functions
 */

#include "config.h"
#include <stdio.h>
#include "mutt/lib.h"
#include "address/lib.h"
#include "email/lib.h"
#include "core/lib.h"
#include "alias/lib.h"
#include "gui/lib.h"
#include "functions.h"
#include "lib.h"
#include "pattern/lib.h"
#include "send/lib.h"
#include "commands.h"
#include "context.h"
#include "hook.h"
#include "index_data.h"
#include "mutt_globals.h"
#include "mutt_header.h"
#include "mutt_mailbox.h"
#include "mutt_menu.h"
#include "mutt_thread.h"
#include "muttlib.h"
#include "opcodes.h"
#include "options.h"
#include "progress.h"
#include "protos.h"
#include "recvattach.h"
#include "score.h"
#ifdef USE_AUTOCRYPT
#include "autocrypt/lib.h"
#endif
#ifdef USE_NOTMUCH
#include "notmuch/lib.h"
#endif
#ifdef USE_IMAP
#include "imap/lib.h"
#endif
#ifdef USE_SIDEBAR
#include "sidebar/lib.h"
#endif
#ifdef USE_NNTP
#include "nntp/lib.h"
#include "nntp/mdata.h"
#endif
#ifdef USE_POP
#include "pop/lib.h"
#endif

struct MuttWindow *win_index = NULL;
struct MuttWindow *win_ibar = NULL;
struct MuttWindow *win_pager = NULL;
struct MuttWindow *win_pbar = NULL;
struct MuttWindow *dlg = NULL;

// -----------------------------------------------------------------------------

/**
 * op_bounce_message - remail a message to another user - Implements ::index_function_t
 */
enum IndexRetval op_bounce_message(struct Menu *menu, int op, struct IndexData *idata)
{
  struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
  el_add_tagged(&el, idata->ctx, idata->cur.e, idata->tag);
  ci_bounce_message(idata->mailbox, &el);
  emaillist_clear(&el);

  return IR_VOID;
}

/**
 * op_check_stats - calculate message statistics for all mailboxes - Implements ::index_function_t
 */
enum IndexRetval op_check_stats(struct Menu *menu, int op, struct IndexData *idata)
{
  mutt_check_stats(idata->mailbox);
  return IR_VOID;
}

/**
 * op_check_traditional - check for classic PGP - Implements ::index_function_t
 */
enum IndexRetval op_check_traditional(struct Menu *menu, int op, struct IndexData *idata)
{
  if (!(WithCrypto & APPLICATION_PGP))
    return IR_NOT_IMPL;
  if (!idata->cur.e)
    return IR_NO_ACTION;

  if (idata->tag || !(idata->cur.e->security & PGP_TRADITIONAL_CHECKED))
  {
    struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
    el_add_tagged(&el, idata->ctx, idata->cur.e, idata->tag);
    mutt_check_traditional_pgp(idata->mailbox, &el, &menu->redraw);
    emaillist_clear(&el);
  }

  if (idata->in_pager)
    return IR_CONTINUE;

  return IR_VOID;
}

/**
 * op_compose_to_sender - compose new message to the current message sender - Implements ::index_function_t
 */
enum IndexRetval op_compose_to_sender(struct Menu *menu, int op, struct IndexData *idata)
{
  struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
  el_add_tagged(&el, idata->ctx, idata->cur.e, idata->tag);
  mutt_send_message(SEND_TO_SENDER, NULL, NULL, idata->ctx, &el, NeoMutt->sub);
  emaillist_clear(&el);
  menu->redraw = REDRAW_FULL;

  return IR_VOID;
}

/**
 * op_create_alias - create an alias from a message sender - Implements ::index_function_t
 */
enum IndexRetval op_create_alias(struct Menu *menu, int op, struct IndexData *idata)
{
  struct AddressList *al = NULL;
  if (idata->cur.e && idata->cur.e->env)
    al = mutt_get_address(idata->cur.e->env, NULL);
  alias_create(al, NeoMutt->sub);
  menu->redraw |= REDRAW_CURRENT;

  return IR_VOID;
}

/**
 * op_delete - delete the current entry - Implements ::index_function_t
 */
enum IndexRetval op_delete(struct Menu *menu, int op, struct IndexData *idata)
{
  /* L10N: CHECK_ACL */
  if (!check_acl(idata->mailbox, MUTT_ACL_DELETE, _("Can't delete message")))
    return IR_ERROR;

  struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
  el_add_tagged(&el, idata->ctx, idata->cur.e, idata->tag);

  mutt_emails_set_flag(idata->mailbox, &el, MUTT_DELETE, 1);
  mutt_emails_set_flag(idata->mailbox, &el, MUTT_PURGE, (op == OP_PURGE_MESSAGE));
  const bool c_delete_untag = cs_subset_bool(NeoMutt->sub, "delete_untag");
  if (c_delete_untag)
    mutt_emails_set_flag(idata->mailbox, &el, MUTT_TAG, 0);
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
      menu->current = ci_next_undeleted(idata->mailbox, menu->current);
      if (menu->current == -1)
      {
        menu->current = menu->oldcurrent;
        menu->redraw |= REDRAW_CURRENT;
      }
      else if (idata->in_pager)
      {
        return IR_CONTINUE;
      }
      else
        menu->redraw |= REDRAW_MOTION_RESYNC;
    }
    else
      menu->redraw |= REDRAW_CURRENT;
  }
  menu->redraw |= REDRAW_STATUS;

  return IR_VOID;
}

/**
 * op_delete_thread - delete all messages in thread - Implements ::index_function_t
 */
enum IndexRetval op_delete_thread(struct Menu *menu, int op, struct IndexData *idata)
{
  /* L10N: CHECK_ACL */
  /* L10N: Due to the implementation details we do not know whether we
     delete zero, 1, 12, ... messages. So in English we use
     "messages". Your language might have other means to express this. */
  if (!check_acl(idata->mailbox, MUTT_ACL_DELETE, _("Can't delete messages")))
    return IR_ERROR;
  if (!idata->cur.e)
    return IR_NO_ACTION;

  int subthread = (op == OP_DELETE_SUBTHREAD);
  int rc = mutt_thread_set_flag(idata->mailbox, idata->cur.e, MUTT_DELETE, true, subthread);
  if (rc == -1)
    return IR_ERROR;
  if (op == OP_PURGE_THREAD)
  {
    rc = mutt_thread_set_flag(idata->mailbox, idata->cur.e, MUTT_PURGE, true, subthread);
    if (rc == -1)
      return IR_ERROR;
  }

  const bool c_delete_untag = cs_subset_bool(NeoMutt->sub, "delete_untag");
  if (c_delete_untag)
    mutt_thread_set_flag(idata->mailbox, idata->cur.e, MUTT_TAG, false, subthread);
  const bool c_resolve = cs_subset_bool(NeoMutt->sub, "resolve");
  if (c_resolve)
  {
    menu->current = ci_next_undeleted(idata->mailbox, menu->current);
    if (menu->current == -1)
      menu->current = menu->oldcurrent;
  }
  menu->redraw |= REDRAW_INDEX | REDRAW_STATUS;

  return IR_SUCCESS;
}

/**
 * op_display_address - display full address of sender - Implements ::index_function_t
 */
enum IndexRetval op_display_address(struct Menu *menu, int op, struct IndexData *idata)
{
  if (!idata->cur.e)
    return IR_NO_ACTION;
  mutt_display_address(idata->cur.e->env);

  return IR_VOID;
}

/**
 * op_display_message - display a message - Implements ::index_function_t
 */
enum IndexRetval op_display_message(struct Menu *menu, int op, struct IndexData *idata)
{
  if (!idata->cur.e)
    return IR_NO_ACTION;
  /* toggle the weeding of headers so that a user can press the key
   * again while reading the message.  */
  if (op == OP_DISPLAY_HEADERS)
    bool_str_toggle(NeoMutt->sub, "weed", NULL);

  OptNeedResort = false;

  if (((C_Sort & SORT_MASK) == SORT_THREADS) && idata->cur.e->collapsed)
  {
    mutt_uncollapse_thread(idata->cur.e);
    mutt_set_vnum(idata->mailbox);
    const bool c_uncollapse_jump =
        cs_subset_bool(NeoMutt->sub, "uncollapse_jump");
    if (c_uncollapse_jump)
      menu->current = mutt_thread_next_unread(idata->cur.e);
  }

  const bool c_pgp_auto_decode =
      cs_subset_bool(NeoMutt->sub, "pgp_auto_decode");
  if (c_pgp_auto_decode && (idata->tag || !(idata->cur.e->security & PGP_TRADITIONAL_CHECKED)))
  {
    struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
    el_add_tagged(&el, idata->ctx, idata->cur.e, idata->tag);
    mutt_check_traditional_pgp(idata->mailbox, &el, &menu->redraw);
    emaillist_clear(&el);
  }
  set_current_email(&idata->cur, mutt_get_virt_email(idata->mailbox, menu->current));

  op = mutt_display_message(win_index, win_ibar, win_pager, win_pbar,
                            idata->mailbox, idata->cur.e);
  window_set_focus(win_index);
  if (op < 0)
  {
    OptNeedResort = false;
    return IR_ERROR;
  }

  /* This is used to redirect a single operation back here afterwards.  If
   * mutt_display_message() returns 0, then this flag and pager state will
   * be cleaned up after this switch statement. */
  idata->in_pager = true;
  menu->oldcurrent = menu->current;
  if (ctx_mailbox(idata->ctx))
    update_index(menu, idata->ctx, MX_STATUS_NEW_MAIL,
                 idata->mailbox->msg_count, &idata->cur);
  //QWQ
  return 0; // continue;
}

/**
 * op_edit_label - add, change, or delete a message's label - Implements ::index_function_t
 */
enum IndexRetval op_edit_label(struct Menu *menu, int op, struct IndexData *idata)
{
  struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
  el_add_tagged(&el, idata->ctx, idata->cur.e, idata->tag);
  int num_changed = mutt_label_message(idata->mailbox, &el);
  emaillist_clear(&el);

  if (num_changed > 0)
  {
    idata->mailbox->changed = true;
    menu->redraw = REDRAW_FULL;
    /* L10N: This is displayed when the x-label on one or more
       messages is edited. */
    mutt_message(ngettext("%d label changed", "%d labels changed", num_changed), num_changed);
    return IR_SUCCESS;
  }

  /* L10N: This is displayed when editing an x-label, but no messages
     were updated.  Possibly due to canceling at the prompt or if the new
     label is the same as the old label. */
  mutt_message(_("No labels changed"));
  return IR_NO_ACTION;
}

/**
 * op_edit_raw_message - edit the raw message (edit and edit-raw-message are synonyms) - Implements ::index_function_t
 */
enum IndexRetval op_edit_raw_message(struct Menu *menu, int op, struct IndexData *idata)
{
  /* TODO split this into 3 cases? */
  bool edit;
  if (op == OP_EDIT_RAW_MESSAGE)
  {
    /* L10N: CHECK_ACL */
    if (!check_acl(idata->mailbox, MUTT_ACL_INSERT, _("Can't edit message")))
      return IR_ERROR;
    edit = true;
  }
  else if (op == OP_EDIT_OR_VIEW_RAW_MESSAGE)
    edit = !idata->mailbox->readonly && (idata->mailbox->rights & MUTT_ACL_INSERT);
  else
    edit = false;

  if (!idata->cur.e)
    return IR_NO_ACTION;
  const bool c_pgp_auto_decode =
      cs_subset_bool(NeoMutt->sub, "pgp_auto_decode");
  if (c_pgp_auto_decode && (idata->tag || !(idata->cur.e->security & PGP_TRADITIONAL_CHECKED)))
  {
    struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
    el_add_tagged(&el, idata->ctx, idata->cur.e, idata->tag);
    mutt_check_traditional_pgp(idata->mailbox, &el, &menu->redraw);
    emaillist_clear(&el);
  }
  struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
  el_add_tagged(&el, idata->ctx, idata->cur.e, idata->tag);
  mutt_ev_message(idata->mailbox, &el, edit ? EVM_EDIT : EVM_VIEW);
  emaillist_clear(&el);
  menu->redraw = REDRAW_FULL;

  return IR_VOID;
}

/**
 * op_edit_type - edit attachment content type - Implements ::index_function_t
 */
enum IndexRetval op_edit_type(struct Menu *menu, int op, struct IndexData *idata)
{
  if (!idata->cur.e)
    return IR_NO_ACTION;
  mutt_edit_content_type(idata->cur.e, idata->cur.e->body, NULL);
  /* if we were in the pager, redisplay the message */
  if (idata->in_pager)
    return IR_CONTINUE;

  menu->redraw = REDRAW_CURRENT;
  return IR_VOID;
}

/**
 * op_end_cond - end of conditional execution (noop) - Implements ::index_function_t
 */
enum IndexRetval op_end_cond(struct Menu *menu, int op, struct IndexData *idata)
{
  return IR_SUCCESS;
}

/**
 * op_enter_command - enter a neomuttrc command - Implements ::index_function_t
 */
enum IndexRetval op_enter_command(struct Menu *menu, int op, struct IndexData *idata)
{
  mutt_enter_command();
  window_set_focus(win_index);
  if (idata->ctx)
    mutt_check_rescore(idata->mailbox);
  menu->redraw = REDRAW_FULL;

  return IR_VOID;
}

/**
 * op_exit - exit this menu - Implements ::index_function_t
 */
enum IndexRetval op_exit(struct Menu *menu, int op, struct IndexData *idata)
{
  idata->close = op;
  if ((!idata->in_pager) && idata->attach_msg)
    return IR_CONTINUE;

  const enum QuadOption c_quit = cs_subset_quad(NeoMutt->sub, "quit");
  if ((!idata->in_pager) &&
      (query_quadoption(c_quit, _("Exit NeoMutt without saving?")) == MUTT_YES))
  {
    if (idata->ctx)
    {
      mx_fastclose_mailbox(idata->mailbox);
      ctx_free(&idata->ctx);
    }
    idata->done = true;
  }

  //QWQ
  return 0;
}

/**
 * op_extract_keys - extract supported public keys - Implements ::index_function_t
 */
enum IndexRetval op_extract_keys(struct Menu *menu, int op, struct IndexData *idata)
{
  if (!WithCrypto)
    return IR_NOT_IMPL;
  struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
  el_add_tagged(&el, idata->ctx, idata->cur.e, idata->tag);
  crypt_extract_keys_from_messages(idata->mailbox, &el);
  emaillist_clear(&el);
  menu->redraw = REDRAW_FULL;

  return IR_VOID;
}

/**
 * op_flag_message - toggle a message's 'important' flag - Implements ::index_function_t
 */
enum IndexRetval op_flag_message(struct Menu *menu, int op, struct IndexData *idata)
{
  /* L10N: CHECK_ACL */
  if (!check_acl(idata->mailbox, MUTT_ACL_WRITE, _("Can't flag message")))
    return IR_ERROR;

  struct Mailbox *m = idata->mailbox;
  if (idata->tag)
  {
    for (size_t i = 0; i < m->msg_count; i++)
    {
      struct Email *e = m->emails[i];
      if (!e)
        break;
      if (message_is_tagged(idata->ctx, e))
        mutt_set_flag(m, e, MUTT_FLAG, !e->flagged);
    }

    menu->redraw |= REDRAW_INDEX;
  }
  else
  {
    if (!idata->cur.e)
      return IR_NO_ACTION;
    mutt_set_flag(m, idata->cur.e, MUTT_FLAG, !idata->cur.e->flagged);
    const bool c_resolve = cs_subset_bool(NeoMutt->sub, "resolve");
    if (c_resolve)
    {
      menu->current = ci_next_undeleted(idata->mailbox, menu->current);
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

  return IR_VOID;
}

/**
 * op_forget_passphrase - wipe passphrases from memory - Implements ::index_function_t
 */
enum IndexRetval op_forget_passphrase(struct Menu *menu, int op, struct IndexData *idata)
{
  crypt_forget_passphrase();
  return IR_VOID;
}

/**
 * op_forward_message - forward a message with comments - Implements ::index_function_t
 */
enum IndexRetval op_forward_message(struct Menu *menu, int op, struct IndexData *idata)
{
  if (!idata->cur.e)
    return IR_NO_ACTION;
  struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
  el_add_tagged(&el, idata->ctx, idata->cur.e, idata->tag);
  const bool c_pgp_auto_decode =
      cs_subset_bool(NeoMutt->sub, "pgp_auto_decode");
  if (c_pgp_auto_decode && (idata->tag || !(idata->cur.e->security & PGP_TRADITIONAL_CHECKED)))
  {
    mutt_check_traditional_pgp(idata->mailbox, &el, &menu->redraw);
  }
  mutt_send_message(SEND_FORWARD, NULL, NULL, idata->ctx, &el, NeoMutt->sub);
  emaillist_clear(&el);
  menu->redraw = REDRAW_FULL;

  return IR_VOID;
}

/**
 * op_group_reply - reply to all recipients - Implements ::index_function_t
 */
enum IndexRetval op_group_reply(struct Menu *menu, int op, struct IndexData *idata)
{
  SendFlags replyflags = SEND_REPLY;
  if (op == OP_GROUP_REPLY)
    replyflags |= SEND_GROUP_REPLY;
  else
    replyflags |= SEND_GROUP_CHAT_REPLY;
  if (!idata->cur.e)
    return IR_NO_ACTION;
  struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
  el_add_tagged(&el, idata->ctx, idata->cur.e, idata->tag);
  const bool c_pgp_auto_decode =
      cs_subset_bool(NeoMutt->sub, "pgp_auto_decode");
  if (c_pgp_auto_decode && (idata->tag || !(idata->cur.e->security & PGP_TRADITIONAL_CHECKED)))
  {
    mutt_check_traditional_pgp(idata->mailbox, &el, &menu->redraw);
  }
  mutt_send_message(replyflags, NULL, NULL, idata->ctx, &el, NeoMutt->sub);
  emaillist_clear(&el);
  menu->redraw = REDRAW_FULL;

  return IR_VOID;
}

/**
 * op_help - this screen - Implements ::index_function_t
 */
enum IndexRetval op_help(struct Menu *menu, int op, struct IndexData *idata)
{
  mutt_help(MENU_MAIN);
  menu->redraw = REDRAW_FULL;
  return IR_VOID;
}

/**
 * op_jump - jump to an index number - Implements ::index_function_t
 */
enum IndexRetval op_jump(struct Menu *menu, int op, struct IndexData *idata)
{
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
  else if ((msg_num < 1) || (msg_num > idata->mailbox->msg_count))
    mutt_error(_("Invalid message number"));
  else if (!idata->mailbox->emails[msg_num - 1]->visible)
    mutt_error(_("That message is not visible"));
  else
  {
    struct Email *e = idata->mailbox->emails[msg_num - 1];

    if (mutt_messages_in_thread(idata->mailbox, e, MIT_POSITION) > 1)
    {
      mutt_uncollapse_thread(e);
      mutt_set_vnum(idata->mailbox);
    }
    menu->current = e->vnum;
  }

  if (idata->in_pager)
    return IR_CONTINUE;

  menu->redraw = REDRAW_FULL;
  //QWQ
  return 0;
}

/**
 * op_list_reply - reply to specified mailing list - Implements ::index_function_t
 */
enum IndexRetval op_list_reply(struct Menu *menu, int op, struct IndexData *idata)
{
  if (!idata->cur.e)
    return IR_NO_ACTION;
  struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
  el_add_tagged(&el, idata->ctx, idata->cur.e, idata->tag);
  const bool c_pgp_auto_decode =
      cs_subset_bool(NeoMutt->sub, "pgp_auto_decode");
  if (c_pgp_auto_decode && (idata->tag || !(idata->cur.e->security & PGP_TRADITIONAL_CHECKED)))
  {
    mutt_check_traditional_pgp(idata->mailbox, &el, &menu->redraw);
  }
  mutt_send_message(SEND_REPLY | SEND_LIST_REPLY, NULL, NULL, idata->ctx, &el,
                    NeoMutt->sub);
  emaillist_clear(&el);
  menu->redraw = REDRAW_FULL;

  return IR_VOID;
}

/**
 * op_mail - compose a new mail message - Implements ::index_function_t
 */
enum IndexRetval op_mail(struct Menu *menu, int op, struct IndexData *idata)
{
  mutt_send_message(SEND_NO_FLAGS, NULL, NULL, idata->ctx, NULL, NeoMutt->sub);
  menu->redraw = REDRAW_FULL;
  return IR_VOID;
}

/**
 * op_mailbox_list - list mailboxes with new mail - Implements ::index_function_t
 */
enum IndexRetval op_mailbox_list(struct Menu *menu, int op, struct IndexData *idata)
{
  mutt_mailbox_list();
  return IR_VOID;
}

/**
 * op_mail_key - mail a PGP public key - Implements ::index_function_t
 */
enum IndexRetval op_mail_key(struct Menu *menu, int op, struct IndexData *idata)
{
  if (!(WithCrypto & APPLICATION_PGP))
    return IR_NOT_IMPL;
  mutt_send_message(SEND_KEY, NULL, NULL, NULL, NULL, NeoMutt->sub);
  menu->redraw = REDRAW_FULL;

  return IR_VOID;
}

/**
 * op_main_break_thread - break the thread in two - Implements ::index_function_t
 */
enum IndexRetval op_main_break_thread(struct Menu *menu, int op, struct IndexData *idata)
{
  /* L10N: CHECK_ACL */
  if (!check_acl(idata->mailbox, MUTT_ACL_WRITE, _("Can't break thread")))
    return IR_ERROR;
  if (!idata->cur.e)
    return IR_NO_ACTION;

  if ((C_Sort & SORT_MASK) != SORT_THREADS)
    mutt_error(_("Threading is not enabled"));
  else if (!STAILQ_EMPTY(&idata->cur.e->env->in_reply_to) ||
           !STAILQ_EMPTY(&idata->cur.e->env->references))
  {
    {
      mutt_break_thread(idata->cur.e);
      mutt_sort_headers(idata->mailbox, idata->ctx->threads, true, &idata->ctx->vsize);
      menu->current = idata->cur.e->vnum;
    }

    idata->mailbox->changed = true;
    mutt_message(_("Thread broken"));

    if (idata->in_pager)
      return IR_CONTINUE;

    menu->redraw |= REDRAW_INDEX;
  }
  else
  {
    mutt_error(_("Thread can't be broken, message is not part of a thread"));
  }

  return IR_VOID;
}

/**
 * op_main_change_folder - open a different folder - Implements ::index_function_t
 */
enum IndexRetval op_main_change_folder(struct Menu *menu, int op, struct IndexData *idata)
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
  if (c_change_folder_next && ctx_mailbox(idata->ctx) &&
      !mutt_buffer_is_empty(&idata->mailbox->pathbuf))
  {
    mutt_buffer_strcpy(folderbuf, mailbox_path(idata->mailbox));
    mutt_buffer_pretty_mailbox(folderbuf);
  }
  /* By default, fill buf with the next mailbox that contains unread mail */
  mutt_mailbox_next(idata->ctx ? idata->mailbox : NULL, folderbuf);

  if (mutt_buffer_enter_fname(cp, folderbuf, true, idata->mailbox, false, NULL,
                              NULL, MUTT_SEL_NO_FLAGS) == -1)
  {
    goto changefoldercleanup;
  }

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
    change_folder_string(menu, folderbuf->data, folderbuf->dsize,
                         &idata->oldcount, &idata->cur, &pager_return, read_only);
  }

changefoldercleanup:
  mutt_buffer_pool_release(&folderbuf);
  if (idata->in_pager && pager_return)
    return IR_CONTINUE;

  //QWQ
  return 0;
}

/**
 * op_main_collapse_all - collapse/uncollapse all threads - Implements ::index_function_t
 */
enum IndexRetval op_main_collapse_all(struct Menu *menu, int op, struct IndexData *idata)
{
  if ((C_Sort & SORT_MASK) != SORT_THREADS)
  {
    mutt_error(_("Threading is not enabled"));
    return IR_ERROR;
  }
  collapse_all(idata->ctx, menu, 1);

  return IR_VOID;
}

/**
 * op_main_collapse_thread - collapse/uncollapse current thread - Implements ::index_function_t
 */
enum IndexRetval op_main_collapse_thread(struct Menu *menu, int op, struct IndexData *idata)
{
  if ((C_Sort & SORT_MASK) != SORT_THREADS)
  {
    mutt_error(_("Threading is not enabled"));
    return IR_ERROR;
  }

  if (!idata->cur.e)
    return IR_NO_ACTION;

  if (idata->cur.e->collapsed)
  {
    menu->current = mutt_uncollapse_thread(idata->cur.e);
    mutt_set_vnum(idata->mailbox);
    const bool c_uncollapse_jump =
        cs_subset_bool(NeoMutt->sub, "uncollapse_jump");
    if (c_uncollapse_jump)
      menu->current = mutt_thread_next_unread(idata->cur.e);
  }
  else if (mutt_thread_can_collapse(idata->cur.e))
  {
    menu->current = mutt_collapse_thread(idata->cur.e);
    mutt_set_vnum(idata->mailbox);
  }
  else
  {
    mutt_error(_("Thread contains unread or flagged messages"));
    return IR_ERROR;
  }

  menu->redraw = REDRAW_INDEX | REDRAW_STATUS;

  return IR_VOID;
}

/**
 * op_main_delete_pattern - delete messages matching a pattern - Implements ::index_function_t
 */
enum IndexRetval op_main_delete_pattern(struct Menu *menu, int op, struct IndexData *idata)
{
  /* L10N: CHECK_ACL */
  /* L10N: Due to the implementation details we do not know whether we
     delete zero, 1, 12, ... messages. So in English we use
     "messages". Your language might have other means to express this.  */
  if (!check_acl(idata->mailbox, MUTT_ACL_DELETE, _("Can't delete messages")))
    return IR_ERROR;

  mutt_pattern_func(Contex2, MUTT_DELETE, _("Delete messages matching: "));
  menu->redraw |= REDRAW_INDEX | REDRAW_STATUS;

  return IR_VOID;
}

/**
 * op_main_limit - limit view to current thread - Implements ::index_function_t
 */
enum IndexRetval op_main_limit(struct Menu *menu, int op, struct IndexData *idata)
{
  const bool lmt = ctx_has_limit(idata->ctx);
  menu->oldcurrent = idata->cur.e ? idata->cur.e->index : -1;
  if (op == OP_TOGGLE_READ)
  {
    char buf2[1024];

    if (!lmt || !mutt_strn_equal(idata->ctx->pattern, "!~R!~D~s", 8))
    {
      snprintf(buf2, sizeof(buf2), "!~R!~D~s%s", lmt ? idata->ctx->pattern : ".*");
    }
    else
    {
      mutt_str_copy(buf2, idata->ctx->pattern + 8, sizeof(buf2));
      if ((*buf2 == '\0') || mutt_strn_equal(buf2, ".*", 2))
        snprintf(buf2, sizeof(buf2), "~A");
    }
    mutt_str_replace(&idata->ctx->pattern, buf2);
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
      for (size_t i = 0; i < idata->mailbox->vcount; i++)
      {
        struct Email *e = mutt_get_virt_email(idata->mailbox, i);
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
    if ((idata->mailbox->msg_count != 0) && ((C_Sort & SORT_MASK) == SORT_THREADS))
    {
      const bool c_collapse_all = cs_subset_bool(NeoMutt->sub, "collapse_all");
      if (c_collapse_all)
        collapse_all(idata->ctx, menu, 0);
      mutt_draw_tree(idata->ctx->threads);
    }
    menu->redraw = REDRAW_FULL;
  }
  if (lmt)
    mutt_message(_("To view all messages, limit to \"all\""));

  return IR_VOID;
}

/**
 * op_main_link_threads - link tagged message to the current one - Implements ::index_function_t
 */
enum IndexRetval op_main_link_threads(struct Menu *menu, int op, struct IndexData *idata)
{
  /* L10N: CHECK_ACL */
  if (!check_acl(idata->mailbox, MUTT_ACL_WRITE, _("Can't link threads")))
    return IR_ERROR;
  if (!idata->cur.e)
    return IR_NO_ACTION;

  if ((C_Sort & SORT_MASK) != SORT_THREADS)
    mutt_error(_("Threading is not enabled"));
  else if (!idata->cur.e->env->message_id)
    mutt_error(_("No Message-ID: header available to link thread"));
  else
  {
    struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
    el_add_tagged(&el, idata->ctx, NULL, true);

    if (mutt_link_threads(idata->cur.e, &el, idata->mailbox))
    {
      mutt_sort_headers(idata->mailbox, idata->ctx->threads, true, &idata->ctx->vsize);
      menu->current = idata->cur.e->vnum;

      idata->mailbox->changed = true;
      mutt_message(_("Threads linked"));
    }
    else
      mutt_error(_("No thread linked"));

    emaillist_clear(&el);
  }

  if (idata->in_pager)
    return IR_CONTINUE;

  menu->redraw |= REDRAW_STATUS | REDRAW_INDEX;
  return IR_VOID;
}

/**
 * op_main_modify_tags - modify (notmuch/imap) tags - Implements ::index_function_t
 */
enum IndexRetval op_main_modify_tags(struct Menu *menu, int op, struct IndexData *idata)
{
  if (!ctx_mailbox(idata->ctx))
    return IR_ERROR;
  struct Mailbox *m = idata->mailbox;
  if (!mx_tags_is_supported(m))
  {
    mutt_message(_("Folder doesn't support tagging, aborting"));
    return IR_ERROR;
  }
  if (!idata->cur.e)
    return IR_NO_ACTION;
  char *tags = NULL;
  if (!idata->tag)
    tags = driver_tags_get_with_hidden(&idata->cur.e->tags);
  char buf[PATH_MAX] = { 0 };
  int rc = mx_tags_edit(m, tags, buf, sizeof(buf));
  FREE(&tags);
  if (rc < 0)
    return IR_ERROR;
  else if (rc == 0)
  {
    mutt_message(_("No tag specified, aborting"));
    return IR_ERROR;
  }

  if (idata->tag)
  {
    struct Progress progress;

    if (m->verbose)
    {
      mutt_progress_init(&progress, _("Update tags..."), MUTT_PROGRESS_WRITE, m->msg_tagged);
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
      if (!message_is_tagged(idata->ctx, e))
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
      return IR_ERROR;
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
      return IR_CONTINUE;

    const bool c_resolve = cs_subset_bool(NeoMutt->sub, "resolve");
    if (c_resolve)
    {
      menu->current = ci_next_undeleted(idata->mailbox, menu->current);
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

  return IR_VOID;
}

/**
 * op_main_next_new - jump to the next new message - Implements ::index_function_t
 */
enum IndexRetval op_main_next_new(struct Menu *menu, int op, struct IndexData *idata)
{
  int first_unread = -1;
  int first_new = -1;

  const int saved_current = menu->current;
  int mcur = menu->current;
  menu->current = -1;
  for (size_t i = 0; i != idata->mailbox->vcount; i++)
  {
    if ((op == OP_MAIN_NEXT_NEW) || (op == OP_MAIN_NEXT_UNREAD) ||
        (op == OP_MAIN_NEXT_NEW_THEN_UNREAD))
    {
      mcur++;
      if (mcur > (idata->mailbox->vcount - 1))
      {
        mcur = 0;
      }
    }
    else
    {
      mcur--;
      if (mcur < 0)
      {
        mcur = idata->mailbox->vcount - 1;
      }
    }

    struct Email *e = mutt_get_virt_email(idata->mailbox, mcur);
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

    if (((op == OP_MAIN_NEXT_UNREAD) || (op == OP_MAIN_PREV_UNREAD)) && (first_unread != -1))
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
      if (ctx_has_limit(idata->ctx))
        mutt_error(_("No new messages in this limited view"));
      else
        mutt_error(_("No new messages"));
    }
    else
    {
      if (ctx_has_limit(idata->ctx))
        mutt_error(_("No unread messages in this limited view"));
      else
        mutt_error(_("No unread messages"));
    }
    return IR_ERROR;
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
    return IR_CONTINUE;

  menu->redraw = REDRAW_MOTION;
  return IR_VOID;
}

/**
 * op_main_next_thread - jump to the next thread - Implements ::index_function_t
 */
enum IndexRetval op_main_next_thread(struct Menu *menu, int op, struct IndexData *idata)
{
  switch (op)
  {
    case OP_MAIN_NEXT_THREAD:
      menu->current = mutt_next_thread(idata->cur.e);
      return IR_ERROR;

    case OP_MAIN_NEXT_SUBTHREAD:
      menu->current = mutt_next_subthread(idata->cur.e);
      return IR_ERROR;

    case OP_MAIN_PREV_THREAD:
      menu->current = mutt_previous_thread(idata->cur.e);
      return IR_ERROR;

    case OP_MAIN_PREV_SUBTHREAD:
      menu->current = mutt_previous_subthread(idata->cur.e);
      return IR_ERROR;
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
    return IR_CONTINUE;
  }
  else
    menu->redraw = REDRAW_MOTION;

  return IR_VOID;
}

/**
 * op_main_next_undeleted - move to the next undeleted message - Implements ::index_function_t
 */
enum IndexRetval op_main_next_undeleted(struct Menu *menu, int op, struct IndexData *idata)
{
  if (menu->current >= (idata->mailbox->vcount - 1))
  {
    if (!idata->in_pager)
      mutt_message(_("You are on the last message"));
    return IR_ERROR;
  }
  menu->current = ci_next_undeleted(idata->mailbox, menu->current);
  if (menu->current == -1)
  {
    menu->current = menu->oldcurrent;
    if (!idata->in_pager)
      mutt_error(_("No undeleted messages"));
  }
  else if (idata->in_pager)
  {
    return IR_CONTINUE;
  }
  else
    menu->redraw = REDRAW_MOTION;

  return IR_VOID;
}

/**
 * op_main_next_unread_mailbox - open next mailbox with new mail - Implements ::index_function_t
 */
enum IndexRetval op_main_next_unread_mailbox(struct Menu *menu, int op, struct IndexData *idata)
{
  struct Mailbox *m = idata->mailbox;

  struct Buffer *folderbuf = mutt_buffer_pool_get();
  mutt_buffer_strcpy(folderbuf, mailbox_path(m));
  m = mutt_mailbox_next(m, folderbuf);
  mutt_buffer_pool_release(&folderbuf);

  if (!m)
  {
    mutt_error(_("No mailboxes have new mail"));
    return IR_ERROR;
  }

  change_folder_mailbox(menu, m, &idata->oldcount, &idata->cur, false);
  return IR_VOID;
}

/**
 * op_main_prev_undeleted - move to the previous undeleted message - Implements ::index_function_t
 */
enum IndexRetval op_main_prev_undeleted(struct Menu *menu, int op, struct IndexData *idata)
{
  if (menu->current < 1)
  {
    mutt_message(_("You are on the first message"));
    return IR_ERROR;
  }
  menu->current = ci_previous_undeleted(idata->mailbox, menu->current);
  if (menu->current == -1)
  {
    menu->current = menu->oldcurrent;
    if (!idata->in_pager)
      mutt_error(_("No undeleted messages"));
  }
  else if (idata->in_pager)
  {
    return IR_CONTINUE;
  }
  else
    menu->redraw = REDRAW_MOTION;

  return IR_VOID;
}

/**
 * op_main_quasi_delete - delete from NeoMutt, don't touch on disk - Implements ::index_function_t
 */
enum IndexRetval op_main_quasi_delete(struct Menu *menu, int op, struct IndexData *idata)
{
  if (idata->tag)
  {
    struct Mailbox *m = idata->mailbox;
    for (size_t i = 0; i < m->msg_count; i++)
    {
      struct Email *e = m->emails[i];
      if (!e)
        break;
      if (message_is_tagged(idata->ctx, e))
      {
        e->quasi_deleted = true;
        m->changed = true;
      }
    }
  }
  else
  {
    if (!idata->cur.e)
      return IR_NO_ACTION;
    idata->cur.e->quasi_deleted = true;
    idata->mailbox->changed = true;
  }

  return IR_VOID;
}

/**
 * op_main_read_thread - mark the current thread as read - Implements ::index_function_t
 */
enum IndexRetval op_main_read_thread(struct Menu *menu, int op, struct IndexData *idata)
{
  /* L10N: CHECK_ACL */
  /* L10N: Due to the implementation details we do not know whether we
     mark zero, 1, 12, ... messages as read. So in English we use
     "messages". Your language might have other means to express this. */
  if (!check_acl(idata->mailbox, MUTT_ACL_SEEN, _("Can't mark messages as read")))
    return IR_ERROR;

  int rc = mutt_thread_set_flag(idata->mailbox, idata->cur.e, MUTT_READ, true,
                                (op != OP_MAIN_READ_THREAD));
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
        return IR_CONTINUE;
      }
    }
    menu->redraw |= REDRAW_INDEX | REDRAW_STATUS;
  }

  return IR_VOID;
}

/**
 * op_main_root_message - jump to root message in thread - Implements ::index_function_t
 */
enum IndexRetval op_main_root_message(struct Menu *menu, int op, struct IndexData *idata)
{
  menu->current = mutt_parent_message(idata->cur.e, op == OP_MAIN_ROOT_MESSAGE);
  if (menu->current < 0)
  {
    menu->current = menu->oldcurrent;
  }
  else if (idata->in_pager)
  {
    return IR_CONTINUE;
  }
  else
    menu->redraw = REDRAW_MOTION;

  return IR_CONTINUE;
}

/**
 * op_main_set_flag - set a status flag on a message - Implements ::index_function_t
 */
enum IndexRetval op_main_set_flag(struct Menu *menu, int op, struct IndexData *idata)
{
  /* check_acl(MUTT_ACL_WRITE); */
  struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
  el_add_tagged(&el, idata->ctx, idata->cur.e, idata->tag);

  if (mutt_change_flag(idata->mailbox, &el, (op == OP_MAIN_SET_FLAG)) == 0)
  {
    menu->redraw |= REDRAW_STATUS;
    const bool c_resolve = cs_subset_bool(NeoMutt->sub, "resolve");
    if (idata->tag)
      menu->redraw |= REDRAW_INDEX;
    else if (c_resolve)
    {
      menu->current = ci_next_undeleted(idata->mailbox, menu->current);
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

  return IR_VOID;
}

/**
 * op_main_show_limit - show currently active limit pattern - Implements ::index_function_t
 */
enum IndexRetval op_main_show_limit(struct Menu *menu, int op, struct IndexData *idata)
{
  if (!ctx_has_limit(idata->ctx))
    mutt_message(_("No limit pattern is in effect"));
  else
  {
    char buf2[256];
    /* L10N: ask for a limit to apply */
    snprintf(buf2, sizeof(buf2), _("Limit: %s"), idata->ctx->pattern);
    mutt_message("%s", buf2);
  }

  return IR_VOID;
}

/**
 * op_main_sync_folder - save changes to mailbox - Implements ::index_function_t
 */
enum IndexRetval op_main_sync_folder(struct Menu *menu, int op, struct IndexData *idata)
{
  int ovc = idata->mailbox->vcount;
  int oc = idata->mailbox->msg_count;
  struct Email *e = NULL;

  /* don't attempt to move the cursor if there are no visible messages in the current limit */
  if (menu->current < idata->mailbox->vcount)
  {
    /* threads may be reordered, so figure out what header the cursor
     * should be on. */
    int newidx = menu->current;
    if (!idata->cur.e)
      return IR_NO_ACTION;
    if (idata->cur.e->deleted)
      newidx = ci_next_undeleted(idata->mailbox, menu->current);
    if (newidx < 0)
      newidx = ci_previous_undeleted(idata->mailbox, menu->current);
    if (newidx >= 0)
      e = mutt_get_virt_email(idata->mailbox, newidx);
  }

  enum MxStatus check = mx_mbox_sync(idata->mailbox);
  if (check == MX_STATUS_OK)
  {
    if (e && (idata->mailbox->vcount != ovc))
    {
      for (size_t i = 0; i < idata->mailbox->vcount; i++)
      {
        struct Email *e2 = mutt_get_virt_email(idata->mailbox, i);
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
    update_index(menu, idata->ctx, check, oc, &idata->cur);
  }

  /* do a sanity check even if mx_mbox_sync failed.  */

  if ((menu->current < 0) ||
      (ctx_mailbox(idata->ctx) && (menu->current >= idata->mailbox->vcount)))
  {
    menu->current = ci_first_message(idata->mailbox);
  }

  /* check for a fatal error, or all messages deleted */
  if (ctx_mailbox(idata->ctx) && mutt_buffer_is_empty(&idata->mailbox->pathbuf))
    ctx_free(&idata->ctx);

  /* if we were in the pager, redisplay the message */
  if (idata->in_pager)
  {
    return IR_CONTINUE;
  }
  else
    menu->redraw = REDRAW_FULL;

  return IR_VOID;
}

/**
 * op_main_tag_pattern - idata->tag messages matching a pattern - Implements ::index_function_t
 */
enum IndexRetval op_main_tag_pattern(struct Menu *menu, int op, struct IndexData *idata)
{
  mutt_pattern_func(Contex2, MUTT_TAG, _("Tag messages matching: "));
  menu->redraw |= REDRAW_INDEX | REDRAW_STATUS;

  return IR_VOID;
}

/**
 * op_main_undelete_pattern - undelete messages matching a pattern - Implements ::index_function_t
 */
enum IndexRetval op_main_undelete_pattern(struct Menu *menu, int op, struct IndexData *idata)
{
  /* L10N: CHECK_ACL */
  /* L10N: Due to the implementation details we do not know whether we
     undelete zero, 1, 12, ... messages. So in English we use
     "messages". Your language might have other means to express this. */
  if (!check_acl(idata->mailbox, MUTT_ACL_DELETE, _("Can't undelete messages")))
    return IR_ERROR;

  if (mutt_pattern_func(Contex2, MUTT_UNDELETE, _("Undelete messages matching: ")) == 0)
  {
    menu->redraw |= REDRAW_INDEX | REDRAW_STATUS;
  }

  return IR_VOID;
}

/**
 * op_main_untag_pattern - untag messages matching a pattern - Implements ::index_function_t
 */
enum IndexRetval op_main_untag_pattern(struct Menu *menu, int op, struct IndexData *idata)
{
  if (mutt_pattern_func(Contex2, MUTT_UNTAG, _("Untag messages matching: ")) == 0)
    menu->redraw |= REDRAW_INDEX | REDRAW_STATUS;

  return IR_VOID;
}

/**
 * op_mark_msg - create a hotkey macro for the current message - Implements ::index_function_t
 */
enum IndexRetval op_mark_msg(struct Menu *menu, int op, struct IndexData *idata)
{
  if (!idata->cur.e)
    return IR_NO_ACTION;
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
      snprintf(macro, sizeof(macro), "<search>~i \"%s\"\n", idata->cur.e->env->message_id);
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

  return IR_VOID;
}

/**
 * op_menu_move - move to the bottom of the page - Implements ::index_function_t
 */
enum IndexRetval op_menu_move(struct Menu *menu, int op, struct IndexData *idata)
{
  switch (op)
  {
    case OP_BOTTOM_PAGE:
      menu_bottom_page(menu);
      return IR_VOID;
    case OP_CURRENT_BOTTOM:
      menu_current_bottom(menu);
      return IR_VOID;
    case OP_CURRENT_MIDDLE:
      menu_current_middle(menu);
      return IR_VOID;
    case OP_CURRENT_TOP:
      menu_current_top(menu);
      return IR_VOID;
    case OP_FIRST_ENTRY:
      menu_first_entry(menu);
      return IR_VOID;
    case OP_HALF_DOWN:
      menu_half_down(menu);
      return IR_VOID;
    case OP_HALF_UP:
      menu_half_up(menu);
      return IR_VOID;
    case OP_LAST_ENTRY:
      menu_last_entry(menu);
      return IR_VOID;
    case OP_MIDDLE_PAGE:
      menu_middle_page(menu);
      return IR_VOID;
    case OP_NEXT_LINE:
      menu_next_line(menu);
      return IR_VOID;
    case OP_NEXT_PAGE:
      menu_next_page(menu);
      return IR_VOID;
    case OP_PREV_LINE:
      menu_prev_line(menu);
      return IR_VOID;
    case OP_PREV_PAGE:
      menu_prev_page(menu);
      return IR_VOID;
    case OP_TOP_PAGE:
      menu_top_page(menu);
      return IR_VOID;
  }

  return IR_ERROR;
}

/**
 * op_next_entry - move to the next entry - Implements ::index_function_t
 */
enum IndexRetval op_next_entry(struct Menu *menu, int op, struct IndexData *idata)
{
  if (menu->current >= (idata->mailbox->vcount - 1))
  {
    if (!idata->in_pager)
      mutt_message(_("You are on the last message"));
    return IR_ERROR;
  }
  menu->current++;
  if (idata->in_pager)
    return IR_CONTINUE;

  menu->redraw = REDRAW_MOTION;
  return IR_VOID;
}

/**
 * op_pipe - pipe message/attachment to a shell command - Implements ::index_function_t
 */
enum IndexRetval op_pipe(struct Menu *menu, int op, struct IndexData *idata)
{
  struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
  el_add_tagged(&el, idata->ctx, idata->cur.e, idata->tag);
  mutt_pipe_message(idata->mailbox, &el);
  emaillist_clear(&el);

#ifdef USE_IMAP
  /* in an IMAP folder index with imap_peek=no, piping could change
   * new or old messages status to read. Redraw what's needed.  */
  const bool c_imap_peek = cs_subset_bool(NeoMutt->sub, "imap_peek");
  if ((idata->mailbox->type == MUTT_IMAP) && !c_imap_peek)
  {
    menu->redraw |= (idata->tag ? REDRAW_INDEX : REDRAW_CURRENT) | REDRAW_STATUS;
  }
#endif

  return IR_VOID;
}

/**
 * op_prev_entry - move to the previous entry - Implements ::index_function_t
 */
enum IndexRetval op_prev_entry(struct Menu *menu, int op, struct IndexData *idata)
{
  if (menu->current < 1)
  {
    if (!idata->in_pager)
      mutt_message(_("You are on the first message"));
    return IR_ERROR;
  }
  menu->current--;
  if (idata->in_pager)
    return IR_CONTINUE;

  menu->redraw = REDRAW_MOTION;
  return IR_VOID;
}

/**
 * op_print - print the current entry - Implements ::index_function_t
 */
enum IndexRetval op_print(struct Menu *menu, int op, struct IndexData *idata)
{
  struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
  el_add_tagged(&el, idata->ctx, idata->cur.e, idata->tag);
  mutt_print_message(idata->mailbox, &el);
  emaillist_clear(&el);

#ifdef USE_IMAP
  /* in an IMAP folder index with imap_peek=no, printing could change
   * new or old messages status to read. Redraw what's needed.  */
  const bool c_imap_peek = cs_subset_bool(NeoMutt->sub, "imap_peek");
  if ((idata->mailbox->type == MUTT_IMAP) && !c_imap_peek)
  {
    menu->redraw |= (idata->tag ? REDRAW_INDEX : REDRAW_CURRENT) | REDRAW_STATUS;
  }
#endif

  return IR_VOID;
}

/**
 * op_query - query external program for addresses - Implements ::index_function_t
 */
enum IndexRetval op_query(struct Menu *menu, int op, struct IndexData *idata)
{
  query_index(NeoMutt->sub);
  return IR_VOID;
}

/**
 * op_quit - save changes to mailbox and quit - Implements ::index_function_t
 */
enum IndexRetval op_quit(struct Menu *menu, int op, struct IndexData *idata)
{
  idata->close = op;
  if (idata->attach_msg)
  {
    idata->done = true;
    return IR_ERROR;
  }

  const enum QuadOption c_quit = cs_subset_quad(NeoMutt->sub, "quit");
  if (query_quadoption(c_quit, _("Quit NeoMutt?")) == MUTT_YES)
  {
    idata->oldcount = (idata->ctx && idata->mailbox) ? idata->mailbox->msg_count : 0;

    mutt_startup_shutdown_hook(MUTT_SHUTDOWN_HOOK);
    notify_send(NeoMutt->notify, NT_GLOBAL, NT_GLOBAL_SHUTDOWN, NULL);

    enum MxStatus check = MX_STATUS_OK;
    if (!idata->ctx || ((check = mx_mbox_close(&idata->ctx)) == MX_STATUS_OK))
    {
      idata->done = true;
    }
    else
    {
      if ((check == MX_STATUS_NEW_MAIL) || (check == MX_STATUS_REOPENED))
      {
        update_index(menu, idata->ctx, check, idata->oldcount, &idata->cur);
      }

      menu->redraw = REDRAW_FULL; /* new mail arrived? */
      OptSearchInvalid = true;
    }
  }

  return IR_VOID;
}

/**
 * op_recall_message - recall a postponed message - Implements ::index_function_t
 */
enum IndexRetval op_recall_message(struct Menu *menu, int op, struct IndexData *idata)
{
  mutt_send_message(SEND_POSTPONED, NULL, NULL, idata->ctx, NULL, NeoMutt->sub);
  menu->redraw = REDRAW_FULL;
  return IR_VOID;
}

/**
 * op_redraw - clear and redraw the screen - Implements ::index_function_t
 */
enum IndexRetval op_redraw(struct Menu *menu, int op, struct IndexData *idata)
{
  mutt_window_reflow(NULL);
  clearok(stdscr, true);
  menu->redraw = REDRAW_FULL;
  return IR_VOID;
}

/**
 * op_resend - use the current message as a template for a new one - Implements ::index_function_t
 */
enum IndexRetval op_resend(struct Menu *menu, int op, struct IndexData *idata)
{
  if (idata->tag)
  {
    struct Mailbox *m = idata->mailbox;
    for (size_t i = 0; i < m->msg_count; i++)
    {
      struct Email *e = m->emails[i];
      if (!e)
        break;
      if (message_is_tagged(idata->ctx, e))
        mutt_resend_message(NULL, idata->ctx, e, NeoMutt->sub);
    }
  }
  else
  {
    mutt_resend_message(NULL, idata->ctx, idata->cur.e, NeoMutt->sub);
  }

  menu->redraw = REDRAW_FULL;
  return IR_VOID;
}

/**
 * op_save - make decrypted copy - Implements ::index_function_t
 */
enum IndexRetval op_save(struct Menu *menu, int op, struct IndexData *idata)
{
  if (((op == OP_DECRYPT_COPY) || (op == OP_DECRYPT_SAVE)) && !WithCrypto)
    return IR_NOT_IMPL;

  struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
  el_add_tagged(&el, idata->ctx, idata->cur.e, idata->tag);

  const enum MessageSaveOpt save_opt =
      ((op == OP_SAVE) || (op == OP_DECODE_SAVE) || (op == OP_DECRYPT_SAVE)) ? SAVE_MOVE : SAVE_COPY;

  enum MessageTransformOpt transform_opt =
      ((op == OP_DECODE_SAVE) || (op == OP_DECODE_COPY))   ? TRANSFORM_DECODE :
      ((op == OP_DECRYPT_SAVE) || (op == OP_DECRYPT_COPY)) ? TRANSFORM_DECRYPT :
                                                             TRANSFORM_NONE;

  const int rc = mutt_save_message(idata->mailbox, &el, save_opt, transform_opt);
  if ((rc == 0) && (save_opt == SAVE_MOVE))
  {
    menu->redraw |= REDRAW_STATUS;
    const bool c_resolve = cs_subset_bool(NeoMutt->sub, "resolve");
    if (idata->tag)
      menu->redraw |= REDRAW_INDEX;
    else if (c_resolve)
    {
      menu->current = ci_next_undeleted(idata->mailbox, menu->current);
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

  return IR_VOID;
}

/**
 * op_search - search for a regular expression - Implements ::index_function_t
 */
enum IndexRetval op_search(struct Menu *menu, int op, struct IndexData *idata)
{
  // Initiating a search can happen on an empty mailbox, but
  // searching for next/previous/... needs to be on a message and
  // thus a non-empty mailbox
  menu->current = mutt_search_command(Contex2, idata->mailbox, menu->current, op);
  if (menu->current == -1)
    menu->current = menu->oldcurrent;
  else
    menu->redraw |= REDRAW_MOTION;

  return IR_VOID;
}

/**
 * op_shell_escape - invoke a command in a subshell - Implements ::index_function_t
 */
enum IndexRetval op_shell_escape(struct Menu *menu, int op, struct IndexData *idata)
{
  if (mutt_shell_escape())
  {
    mutt_mailbox_check(ctx_mailbox(idata->ctx), MUTT_MAILBOX_CHECK_FORCE);
  }

  return IR_VOID;
}

/**
 * op_show_log_messages - show log (and debug) messages - Implements ::index_function_t
 */
enum IndexRetval op_show_log_messages(struct Menu *menu, int op, struct IndexData *idata)
{
  char tempfile[PATH_MAX];
  mutt_mktemp(tempfile, sizeof(tempfile));

  FILE *fp = mutt_file_fopen(tempfile, "a+");
  if (!fp)
  {
    mutt_perror("fopen");
    return IR_ERROR;
  }

  log_queue_save(fp);
  mutt_file_fclose(&fp);

  mutt_do_pager("messages", tempfile, MUTT_PAGER_LOGS, NULL);

  return IR_VOID;
}

/**
 * op_sort - sort messages - Implements ::index_function_t
 */
enum IndexRetval op_sort(struct Menu *menu, int op, struct IndexData *idata)
{
  if (mutt_select_sort((op == OP_SORT_REVERSE)) != 0)
    return IR_ERROR;

  if (ctx_mailbox(idata->ctx) && (idata->mailbox->msg_count != 0))
  {
    resort_index(idata->ctx, menu);
    OptSearchInvalid = true;
  }
  if (idata->in_pager)
    return IR_CONTINUE;

  menu->redraw |= REDRAW_STATUS;
  return IR_VOID;
}

/**
 * op_tag - idata->tag the current entry - Implements ::index_function_t
 */
enum IndexRetval op_tag(struct Menu *menu, int op, struct IndexData *idata)
{
  const bool c_auto_tag = cs_subset_bool(NeoMutt->sub, "auto_tag");
  if (idata->tag && !c_auto_tag)
  {
    struct Mailbox *m = idata->mailbox;
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
      return IR_NO_ACTION;
    mutt_set_flag(idata->mailbox, idata->cur.e, MUTT_TAG, !idata->cur.e->tagged);

    menu->redraw |= REDRAW_STATUS;
    const bool c_resolve = cs_subset_bool(NeoMutt->sub, "resolve");
    if (c_resolve && (menu->current < idata->mailbox->vcount - 1))
    {
      menu->current++;
      menu->redraw |= REDRAW_MOTION_RESYNC;
    }
    else
      menu->redraw |= REDRAW_CURRENT;
  }

  return IR_VOID;
}

/**
 * op_tag_thread - idata->tag the current thread - Implements ::index_function_t
 */
enum IndexRetval op_tag_thread(struct Menu *menu, int op, struct IndexData *idata)
{
  if (!idata->cur.e)
    return IR_NO_ACTION;

  int rc = mutt_thread_set_flag(idata->mailbox, idata->cur.e, MUTT_TAG,
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

  return IR_VOID;
}

/**
 * op_toggle_new - toggle a message's 'new' flag - Implements ::index_function_t
 */
enum IndexRetval op_toggle_new(struct Menu *menu, int op, struct IndexData *idata)
{
  /* L10N: CHECK_ACL */
  if (!check_acl(idata->mailbox, MUTT_ACL_SEEN, _("Can't toggle new")))
    return IR_ERROR;

  struct Mailbox *m = idata->mailbox;
  if (idata->tag)
  {
    for (size_t i = 0; i < m->msg_count; i++)
    {
      struct Email *e = m->emails[i];
      if (!e)
        break;
      if (!message_is_tagged(idata->ctx, e))
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
      return IR_NO_ACTION;
    if (idata->cur.e->read || idata->cur.e->old)
      mutt_set_flag(m, idata->cur.e, MUTT_NEW, true);
    else
      mutt_set_flag(m, idata->cur.e, MUTT_READ, true);

    const bool c_resolve = cs_subset_bool(NeoMutt->sub, "resolve");
    if (c_resolve)
    {
      menu->current = ci_next_undeleted(idata->mailbox, menu->current);
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

  return IR_VOID;
}

/**
 * op_toggle_write - toggle whether the mailbox will be rewritten - Implements ::index_function_t
 */
enum IndexRetval op_toggle_write(struct Menu *menu, int op, struct IndexData *idata)
{
  if (mx_toggle_write(idata->mailbox) == 0)
  {
    if (idata->in_pager)
      return IR_CONTINUE;

    menu->redraw |= REDRAW_STATUS;
  }

  return IR_VOID;
}

/**
 * op_undelete - undelete the current entry - Implements ::index_function_t
 */
enum IndexRetval op_undelete(struct Menu *menu, int op, struct IndexData *idata)
{
  /* L10N: CHECK_ACL */
  if (!check_acl(idata->mailbox, MUTT_ACL_DELETE, _("Can't undelete message")))
    return IR_ERROR;

  struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
  el_add_tagged(&el, idata->ctx, idata->cur.e, idata->tag);

  mutt_emails_set_flag(idata->mailbox, &el, MUTT_DELETE, 0);
  mutt_emails_set_flag(idata->mailbox, &el, MUTT_PURGE, 0);
  emaillist_clear(&el);

  if (idata->tag)
  {
    menu->redraw |= REDRAW_INDEX;
  }
  else
  {
    const bool c_resolve = cs_subset_bool(NeoMutt->sub, "resolve");
    if (c_resolve && (menu->current < (idata->mailbox->vcount - 1)))
    {
      menu->current++;
      menu->redraw |= REDRAW_MOTION_RESYNC;
    }
    else
      menu->redraw |= REDRAW_CURRENT;
  }

  menu->redraw |= REDRAW_STATUS;

  return IR_VOID;
}

/**
 * op_undelete_thread - undelete all messages in thread - Implements ::index_function_t
 */
enum IndexRetval op_undelete_thread(struct Menu *menu, int op, struct IndexData *idata)
{
  /* L10N: CHECK_ACL */
  /* L10N: Due to the implementation details we do not know whether we
     undelete zero, 1, 12, ... messages. So in English we use
     "messages". Your language might have other means to express this. */
  if (!check_acl(idata->mailbox, MUTT_ACL_DELETE, _("Can't undelete messages")))
    return IR_ERROR;

  int rc = mutt_thread_set_flag(idata->mailbox, idata->cur.e, MUTT_DELETE,
                                false, (op != OP_UNDELETE_THREAD));
  if (rc != -1)
  {
    rc = mutt_thread_set_flag(idata->mailbox, idata->cur.e, MUTT_PURGE, false,
                              (op != OP_UNDELETE_THREAD));
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

  return IR_VOID;
}

/**
 * op_version - show the NeoMutt version number and date - Implements ::index_function_t
 */
enum IndexRetval op_version(struct Menu *menu, int op, struct IndexData *idata)
{
  mutt_message(mutt_make_version());
  return IR_VOID;
}

/**
 * op_view_attachments - show MIME attachments - Implements ::index_function_t
 */
enum IndexRetval op_view_attachments(struct Menu *menu, int op, struct IndexData *idata)
{
  if (!idata->cur.e)
    return IR_NO_ACTION;
  dlg_select_attachment(idata->cur.e);
  if (idata->cur.e->attach_del)
    idata->mailbox->changed = true;
  menu->redraw = REDRAW_FULL;
  return IR_VOID;
}

/**
 * op_what_key - display the keycode for a key press - Implements ::index_function_t
 */
enum IndexRetval op_what_key(struct Menu *menu, int op, struct IndexData *idata)
{
  mutt_what_key();
  return IR_VOID;
}

// -----------------------------------------------------------------------------

#ifdef USE_AUTOCRYPT
/**
 * op_autocrypt_acct_menu - manage autocrypt accounts - Implements ::index_function_t
 */
enum IndexRetval op_autocrypt_acct_menu(struct Menu *menu, int op, struct IndexData *idata)
{
  dlg_select_autocrypt_account(idata->mailbox);
  return IR_VOID;
}
#endif

#ifdef USE_IMAP
/**
 * op_main_imap_fetch - force retrieval of mail from IMAP server - Implements ::index_function_t
 */
enum IndexRetval op_main_imap_fetch(struct Menu *menu, int op, struct IndexData *idata)
{
  if (ctx_mailbox(idata->ctx) && (idata->mailbox->type == MUTT_IMAP))
    imap_check_mailbox(idata->mailbox, true);
  return IR_VOID;
}

/**
 * op_main_imap_logout_all - logout from all IMAP servers - Implements ::index_function_t
 */
enum IndexRetval op_main_imap_logout_all(struct Menu *menu, int op, struct IndexData *idata)
{
  if (ctx_mailbox(idata->ctx) && (idata->mailbox->type == MUTT_IMAP))
  {
    const enum MxStatus check = mx_mbox_close(&idata->ctx);
    if (check != MX_STATUS_OK)
    {
      if ((check == MX_STATUS_NEW_MAIL) || (check == MX_STATUS_REOPENED))
      {
        update_index(menu, idata->ctx, check, idata->oldcount, &idata->cur);
      }
      OptSearchInvalid = true;
      menu->redraw = REDRAW_FULL;
      return IR_ERROR;
    }
  }
  imap_logout_all();
  mutt_message(_("Logged out of IMAP servers"));
  OptSearchInvalid = true;
  menu->redraw = REDRAW_FULL;

  return IR_VOID;
}
#endif

#ifdef USE_NNTP
/**
 * op_catchup - mark all articles in newsgroup as read - Implements ::index_function_t
 */
enum IndexRetval op_catchup(struct Menu *menu, int op, struct IndexData *idata)
{
  if (idata->ctx && (idata->mailbox->type == MUTT_NNTP))
  {
    struct NntpMboxData *mdata = idata->mailbox->mdata;
    if (mutt_newsgroup_catchup(idata->mailbox, mdata->adata, mdata->group))
      menu->redraw = REDRAW_INDEX | REDRAW_STATUS;
  }

  return IR_VOID;
}

/**
 * op_get_children - get all children of the current message - Implements ::index_function_t
 */
enum IndexRetval op_get_children(struct Menu *menu, int op, struct IndexData *idata)
{
  if (idata->mailbox->type != MUTT_NNTP)
    return IR_ERROR;

  if (!idata->cur.e)
    return IR_NO_ACTION;

  char buf[PATH_MAX] = { 0 };
  int oldmsgcount = idata->mailbox->msg_count;
  int oldindex = idata->cur.e->index;
  int rc = 0;

  if (!idata->cur.e->env->message_id)
  {
    mutt_error(_("No Message-Id. Unable to perform operation."));
    return IR_ERROR;
  }

  mutt_message(_("Fetching message headers..."));
  if (!idata->mailbox->id_hash)
    idata->mailbox->id_hash = mutt_make_id_hash(idata->mailbox);
  mutt_str_copy(buf, idata->cur.e->env->message_id, sizeof(buf));

  /* trying to find msgid of the root message */
  if (op == OP_RECONSTRUCT_THREAD)
  {
    struct ListNode *ref = NULL;
    STAILQ_FOREACH(ref, &idata->cur.e->env->references, entries)
    {
      if (!mutt_hash_find(idata->mailbox->id_hash, ref->data))
      {
        rc = nntp_check_msgid(idata->mailbox, ref->data);
        if (rc < 0)
          return IR_ERROR;
      }

      /* the last msgid in References is the root message */
      if (!STAILQ_NEXT(ref, entries))
        mutt_str_copy(buf, ref->data, sizeof(buf));
    }
  }

  /* fetching all child messages */
  if (rc >= 0)
    rc = nntp_check_children(idata->mailbox, buf);

  /* at least one message has been loaded */
  if (idata->mailbox->msg_count > oldmsgcount)
  {
    struct Email *e_oldcur = mutt_get_virt_email(idata->mailbox, menu->current);
    bool verbose = idata->mailbox->verbose;

    if (rc < 0)
      idata->mailbox->verbose = false;
    mutt_sort_headers(idata->mailbox, idata->ctx->threads,
                      (op == OP_RECONSTRUCT_THREAD), &idata->ctx->vsize);
    idata->mailbox->verbose = verbose;

    /* Similar to OP_MAIN_ENTIRE_THREAD, keep displaying the old message, but
     * update the index */
    if (idata->in_pager)
    {
      menu->current = e_oldcur->vnum;
      menu->redraw = REDRAW_STATUS | REDRAW_INDEX;
      return IR_CONTINUE;
    }

    /* if the root message was retrieved, move to it */
    struct Email *e = mutt_hash_find(idata->mailbox->id_hash, buf);
    if (e)
      menu->current = e->vnum;
    else
    {
      /* try to restore old position */
      for (int i = 0; i < idata->mailbox->msg_count; i++)
      {
        e = idata->mailbox->emails[i];
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
      return IR_CONTINUE;
    }
  }

  return IR_VOID;
}

/**
 * op_get_message - get parent of the current message - Implements ::index_function_t
 */
enum IndexRetval op_get_message(struct Menu *menu, int op, struct IndexData *idata)
{
  char buf[PATH_MAX] = { 0 };
  if (idata->mailbox->type == MUTT_NNTP)
  {
    if (op == OP_GET_MESSAGE)
    {
      if ((mutt_get_field(_("Enter Message-Id: "), buf, sizeof(buf),
                          MUTT_COMP_NO_FLAGS, false, NULL, NULL) != 0) ||
          (buf[0] == '\0'))
      {
        return IR_ERROR;
      }
    }
    else
    {
      if (!idata->cur.e || STAILQ_EMPTY(&idata->cur.e->env->references))
      {
        mutt_error(_("Article has no parent reference"));
        return IR_ERROR;
      }
      mutt_str_copy(buf, STAILQ_FIRST(&idata->cur.e->env->references)->data, sizeof(buf));
    }
    if (!idata->mailbox->id_hash)
      idata->mailbox->id_hash = mutt_make_id_hash(idata->mailbox);
    struct Email *e = mutt_hash_find(idata->mailbox->id_hash, buf);
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
        mutt_set_vnum(idata->mailbox);
        menu->current = e->vnum;
        menu->redraw = REDRAW_MOTION_RESYNC;
      }
      else
        mutt_error(_("Message is not visible in limited view"));
    }
    else
    {
      mutt_message(_("Fetching %s from server..."), buf);
      int rc = nntp_check_msgid(idata->mailbox, buf);
      if (rc == 0)
      {
        e = idata->mailbox->emails[idata->mailbox->msg_count - 1];
        mutt_sort_headers(idata->mailbox, idata->ctx->threads, false,
                          &idata->ctx->vsize);
        menu->current = e->vnum;
        menu->redraw = REDRAW_FULL;
      }
      else if (rc > 0)
        mutt_error(_("Article %s not found on the server"), buf);
    }
  }

  return IR_VOID;
}

/**
 * op_main_change_group - open a different newsgroup - Implements ::index_function_t
 */
enum IndexRetval op_main_change_group(struct Menu *menu, int op, struct IndexData *idata)
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
  if (c_change_folder_next && ctx_mailbox(idata->ctx) &&
      !mutt_buffer_is_empty(&idata->mailbox->pathbuf))
  {
    mutt_buffer_strcpy(folderbuf, mailbox_path(idata->mailbox));
    mutt_buffer_pretty_mailbox(folderbuf);
  }

  OptNews = true;
  const char *c_news_server = cs_subset_string(NeoMutt->sub, "news_server");
  CurrentNewsSrv =
      nntp_select_server(idata->ctx ? idata->mailbox : NULL, c_news_server, false);
  if (!CurrentNewsSrv)
    goto changefoldercleanup2;

  nntp_mailbox(idata->ctx ? idata->mailbox : NULL, folderbuf->data, folderbuf->dsize);

  if (mutt_buffer_enter_fname(cp, folderbuf, true, idata->mailbox, false, NULL,
                              NULL, MUTT_SEL_NO_FLAGS) == -1)
  {
    goto changefoldercleanup2;
  }

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
    change_folder_string(menu, folderbuf->data, folderbuf->dsize,
                         &idata->oldcount, &idata->cur, &pager_return, read_only);
  }
  dlg->help_data = IndexNewsHelp;

changefoldercleanup2:
  mutt_buffer_pool_release(&folderbuf);
  if (idata->in_pager && pager_return)
    return IR_CONTINUE;

  return IR_VOID;
}

/**
 * op_post - followup to newsgroup - Implements ::index_function_t
 */
enum IndexRetval op_post(struct Menu *menu, int op, struct IndexData *idata)
{
  // case OP_POST:
  if (!idata->cur.e)
    return IR_NO_ACTION;

  const enum QuadOption c_followup_to_poster =
      cs_subset_quad(NeoMutt->sub, "followup_to_poster");
  if ((op != OP_FOLLOWUP) || !idata->cur.e->env->followup_to ||
      !mutt_istr_equal(idata->cur.e->env->followup_to, "poster") ||
      (query_quadoption(c_followup_to_poster,
                        _("Reply by mail as poster prefers?")) != MUTT_YES))
  {
    const enum QuadOption c_post_moderated =
        cs_subset_quad(NeoMutt->sub, "post_moderated");
    if (idata->ctx && (idata->mailbox->type == MUTT_NNTP) &&
        !((struct NntpMboxData *) idata->mailbox->mdata)->allowed && (query_quadoption(c_post_moderated, _("Posting to this group not allowed, may be moderated. Continue?")) != MUTT_YES))
    {
      return IR_ERROR;
    }
    if (op == OP_POST)
      mutt_send_message(SEND_NEWS, NULL, NULL, idata->ctx, NULL, NeoMutt->sub);
    else
    {
      struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
      el_add_tagged(&el, idata->ctx, idata->cur.e, idata->tag);
      mutt_send_message(((op == OP_FOLLOWUP) ? SEND_REPLY : SEND_FORWARD) | SEND_NEWS,
                        NULL, NULL, idata->ctx, &el, NeoMutt->sub);
      emaillist_clear(&el);
    }
    menu->redraw = REDRAW_FULL;
    return IR_VOID;
  }

  // case OP_REPLY:
  {
    if (!idata->cur.e)
      return IR_NO_ACTION;
    struct EmailList el = STAILQ_HEAD_INITIALIZER(el);
    el_add_tagged(&el, idata->ctx, idata->cur.e, idata->tag);
    const bool c_pgp_auto_decode =
        cs_subset_bool(NeoMutt->sub, "pgp_auto_decode");
    if (c_pgp_auto_decode &&
        (idata->tag || !(idata->cur.e->security & PGP_TRADITIONAL_CHECKED)))
    {
      mutt_check_traditional_pgp(idata->mailbox, &el, &menu->redraw);
    }
    mutt_send_message(SEND_REPLY, NULL, NULL, idata->ctx, &el, NeoMutt->sub);
    emaillist_clear(&el);
    menu->redraw = REDRAW_FULL;
    return IR_VOID;
  }

  //QWQ
  return 0;
}
#endif

#ifdef USE_NOTMUCH
/**
 * op_main_entire_thread - read entire thread of the current message - Implements ::index_function_t
 */
enum IndexRetval op_main_entire_thread(struct Menu *menu, int op, struct IndexData *idata)
{
  char buf[PATH_MAX] = { 0 };
  if (idata->mailbox->type != MUTT_NOTMUCH)
  {
    if (((idata->mailbox->type != MUTT_MH) && (idata->mailbox->type != MUTT_MAILDIR)) ||
        (!idata->cur.e || !idata->cur.e->env || !idata->cur.e->env->message_id))
    {
      mutt_message(_("No virtual folder and no Message-Id, aborting"));
      return IR_ERROR;
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
    if (idata->mailbox->msg_count == 0)
    {
      mutt_error(_("failed to find message in notmuch database. try "
                   "running 'notmuch new'."));
      return IR_ERROR;
    }
  }
  idata->oldcount = idata->mailbox->msg_count;
  struct Email *e_oldcur = mutt_get_virt_email(idata->mailbox, menu->current);
  if (nm_read_entire_thread(idata->mailbox, e_oldcur) < 0)
  {
    mutt_message(_("Failed to read thread, aborting"));
    return IR_ERROR;
  }
  if (idata->oldcount < idata->mailbox->msg_count)
  {
    /* nm_read_entire_thread() triggers mutt_sort_headers() if necessary */
    menu->current = e_oldcur->vnum;
    menu->redraw = REDRAW_STATUS | REDRAW_INDEX;

    if (e_oldcur->collapsed || idata->ctx->collapsed)
    {
      menu->current = mutt_uncollapse_thread(e_oldcur);
      mutt_set_vnum(idata->mailbox);
    }
  }
  if (idata->in_pager)
    return IR_CONTINUE;

  return IR_VOID;
}

/**
 * op_main_vfolder_from_query - generate virtual folder from query - Implements ::index_function_t
 */
enum IndexRetval op_main_vfolder_from_query(struct Menu *menu, int op, struct IndexData *idata)
{
  char buf[PATH_MAX] = { 0 };
  if ((mutt_get_field("Query: ", buf, sizeof(buf), MUTT_NM_QUERY, false, NULL, NULL) != 0) ||
      (buf[0] == '\0'))
  {
    mutt_message(_("No query, aborting"));
    return IR_NO_ACTION;
  }

  // Keep copy of user's query to name the mailbox
  char *query_unencoded = mutt_str_dup(buf);

  struct Mailbox *m_query =
      change_folder_notmuch(menu, buf, sizeof(buf), &idata->oldcount, &idata->cur,
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

  return IR_VOID;
}

/**
 * op_main_windowed_vfolder_backward - shifts virtual folder time window backwards - Implements ::index_function_t
 */
enum IndexRetval op_main_windowed_vfolder_backward(struct Menu *menu, int op,
                                                   struct IndexData *idata)
{
  const short c_nm_query_window_duration =
      cs_subset_number(NeoMutt->sub, "nm_query_window_duration");
  if (c_nm_query_window_duration <= 0)
  {
    mutt_message(_("Windowed queries disabled"));
    return IR_ERROR;
  }
  const char *c_nm_query_window_current_search =
      cs_subset_string(NeoMutt->sub, "nm_query_window_current_search");
  if (!c_nm_query_window_current_search)
  {
    mutt_message(_("No notmuch vfolder currently loaded"));
    return IR_ERROR;
  }
  nm_query_window_backward();
  char buf[PATH_MAX] = { 0 };
  mutt_str_copy(buf, c_nm_query_window_current_search, sizeof(buf));
  change_folder_notmuch(menu, buf, sizeof(buf), &idata->oldcount, &idata->cur, false);

  return IR_CONTINUE;
}

/**
 * op_main_windowed_vfolder_forward - shifts virtual folder time window forwards - Implements ::index_function_t
 */
enum IndexRetval op_main_windowed_vfolder_forward(struct Menu *menu, int op,
                                                  struct IndexData *idata)
{
  const short c_nm_query_window_duration =
      cs_subset_number(NeoMutt->sub, "nm_query_window_duration");
  if (c_nm_query_window_duration <= 0)
  {
    mutt_message(_("Windowed queries disabled"));
    return IR_ERROR;
  }
  const char *c_nm_query_window_current_search =
      cs_subset_string(NeoMutt->sub, "nm_query_window_current_search");
  if (!c_nm_query_window_current_search)
  {
    mutt_message(_("No notmuch vfolder currently loaded"));
    return IR_ERROR;
  }
  nm_query_window_forward();
  char buf[PATH_MAX] = { 0 };
  mutt_str_copy(buf, c_nm_query_window_current_search, sizeof(buf));
  change_folder_notmuch(menu, buf, sizeof(buf), &idata->oldcount, &idata->cur, false);

  return IR_VOID;
}
#endif

#ifdef USE_POP
/**
 * op_main_fetch_mail - retrieve mail from POP server - Implements ::index_function_t
 */
enum IndexRetval op_main_fetch_mail(struct Menu *menu, int op, struct IndexData *idata)
{
  pop_fetch_mail();
  menu->redraw = REDRAW_FULL;
  return IR_VOID;
}
#endif

#ifdef USE_SIDEBAR
/**
 * op_sidebar_next - move the highlight to the first mailbox - Implements ::index_function_t
 */
enum IndexRetval op_sidebar_next(struct Menu *menu, int op, struct IndexData *idata)
{
  struct MuttWindow *win_sidebar = mutt_window_find(dlg, WT_SIDEBAR);
  sb_change_mailbox(win_sidebar, op);
  return IR_VOID;
}

/**
 * op_sidebar_open - open highlighted mailbox - Implements ::index_function_t
 */
enum IndexRetval op_sidebar_open(struct Menu *menu, int op, struct IndexData *idata)
{
  struct MuttWindow *win_sidebar = mutt_window_find(dlg, WT_SIDEBAR);
  change_folder_mailbox(menu, sb_get_highlight(win_sidebar), &idata->oldcount,
                        &idata->cur, false);
  return IR_VOID;
}

/**
 * op_sidebar_toggle_visible - make the sidebar (in)visible - Implements ::index_function_t
 */
enum IndexRetval op_sidebar_toggle_visible(struct Menu *menu, int op, struct IndexData *idata)
{
  bool_str_toggle(NeoMutt->sub, "sidebar_visible", NULL);
  mutt_window_reflow(NULL);
  return IR_VOID;
}
#endif

// -----------------------------------------------------------------------------

/**
 * IndexFunctions - XXX
 */
struct IndexFunction IndexFunctions[] = {
  // clang-format off
  { OP_BOTTOM_PAGE,                      op_menu_move,                      CHECK_NO_FLAGS },
  { OP_BOUNCE_MESSAGE,                   op_bounce_message,                 CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_ATTACH },
  { OP_CHECK_STATS,                      op_check_stats,                    CHECK_NO_FLAGS },
  { OP_CHECK_TRADITIONAL,                op_check_traditional,              CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_COMPOSE_TO_SENDER,                op_compose_to_sender,              CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_ATTACH },
  { OP_COPY_MESSAGE,                     op_save,                           CHECK_NO_FLAGS },
  { OP_CREATE_ALIAS,                     op_create_alias,                   CHECK_NO_FLAGS },
  { OP_CURRENT_BOTTOM,                   op_menu_move,                      CHECK_NO_FLAGS },
  { OP_CURRENT_MIDDLE,                   op_menu_move,                      CHECK_NO_FLAGS },
  { OP_CURRENT_TOP,                      op_menu_move,                      CHECK_NO_FLAGS },
  { OP_DECODE_COPY,                      op_save,                           CHECK_NO_FLAGS },
  { OP_DECODE_SAVE,                      op_save,                           CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_DECRYPT_COPY,                     op_save,                           CHECK_NO_FLAGS },
  { OP_DECRYPT_SAVE,                     op_save,                           CHECK_NO_FLAGS },
  { OP_DELETE,                           op_delete,                         CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY },
  { OP_DELETE_SUBTHREAD,                 op_delete_thread,                  CHECK_NO_FLAGS },
  { OP_DELETE_THREAD,                    op_delete_thread,                  CHECK_NO_FLAGS },
  { OP_DISPLAY_ADDRESS,                  op_display_address,                CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_DISPLAY_HEADERS,                  op_display_message,                CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_DISPLAY_MESSAGE,                  op_display_message,                CHECK_NO_FLAGS },
  { OP_EDIT_LABEL,                       op_edit_label,                     CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY },
  { OP_EDIT_OR_VIEW_RAW_MESSAGE,         op_edit_raw_message,               CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_ATTACH },
  { OP_EDIT_RAW_MESSAGE,                 op_edit_raw_message,               CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_ATTACH | CHECK_READONLY },
  { OP_EDIT_TYPE,                        op_edit_type,                      CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_ATTACH },
  { OP_END_COND,                         op_end_cond,                       CHECK_NO_FLAGS },
  { OP_ENTER_COMMAND,                    op_enter_command,                  CHECK_NO_FLAGS },
  { OP_EXIT,                             op_exit,                           CHECK_NO_FLAGS },
  { OP_EXTRACT_KEYS,                     op_extract_keys,                   CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_FIRST_ENTRY,                      op_menu_move,                      CHECK_NO_FLAGS },
  { OP_FLAG_MESSAGE,                     op_flag_message,                   CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY },
  { OP_FORGET_PASSPHRASE,                op_forget_passphrase,              CHECK_NO_FLAGS },
  { OP_FORWARD_MESSAGE,                  op_forward_message,                CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_ATTACH },
  { OP_GROUP_CHAT_REPLY,                 op_group_reply,                    CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_ATTACH },
  { OP_GROUP_REPLY,                      op_group_reply,                    CHECK_NO_FLAGS },
  { OP_HALF_DOWN,                        op_menu_move,                      CHECK_NO_FLAGS },
  { OP_HALF_UP,                          op_menu_move,                      CHECK_NO_FLAGS },
  { OP_HELP,                             op_help,                           CHECK_NO_FLAGS },
  { OP_JUMP,                             op_jump,                           CHECK_IN_MAILBOX },
  { OP_LAST_ENTRY,                       op_menu_move,                      CHECK_NO_FLAGS },
  { OP_LIMIT_CURRENT_THREAD,             op_main_limit,                     CHECK_NO_FLAGS },
  { OP_LIST_REPLY,                       op_list_reply,                     CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_ATTACH },
  { OP_MAIL,                             op_mail,                           CHECK_ATTACH },
  { OP_MAILBOX_LIST,                     op_mailbox_list,                   CHECK_NO_FLAGS },
  { OP_MAIL_KEY,                         op_mail_key,                       CHECK_ATTACH },
  { OP_MAIN_BREAK_THREAD,                op_main_break_thread,              CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY },
  { OP_MAIN_CHANGE_FOLDER,               op_main_change_folder,             CHECK_NO_FLAGS },
  { OP_MAIN_CHANGE_FOLDER_READONLY,      op_main_change_folder,             CHECK_NO_FLAGS },
  { OP_MAIN_CLEAR_FLAG,                  op_main_set_flag,                  CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY },
  { OP_MAIN_COLLAPSE_ALL,                op_main_collapse_all,              CHECK_IN_MAILBOX },
  { OP_MAIN_COLLAPSE_THREAD,             op_main_collapse_thread,           CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_DELETE_PATTERN,              op_main_delete_pattern,            CHECK_IN_MAILBOX | CHECK_READONLY | CHECK_ATTACH },
  { OP_MAIN_LIMIT,                       op_main_limit,                     CHECK_NO_FLAGS },
  { OP_MAIN_LINK_THREADS,                op_main_link_threads,              CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY },
  { OP_MAIN_MODIFY_TAGS,                 op_main_modify_tags,               CHECK_NO_FLAGS },
  { OP_MAIN_MODIFY_TAGS_THEN_HIDE,       op_main_modify_tags,               CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY },
  { OP_MAIN_NEXT_NEW,                    op_main_next_new,                  CHECK_NO_FLAGS },
  { OP_MAIN_NEXT_NEW_THEN_UNREAD,        op_main_next_new,                  CHECK_NO_FLAGS },
  { OP_MAIN_NEXT_SUBTHREAD,              op_main_next_thread,               CHECK_NO_FLAGS },
  { OP_MAIN_NEXT_THREAD,                 op_main_next_thread,               CHECK_NO_FLAGS },
  { OP_MAIN_NEXT_UNDELETED,              op_main_next_undeleted,            CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_NEXT_UNREAD,                 op_main_next_new,                  CHECK_NO_FLAGS },
  { OP_MAIN_NEXT_UNREAD_MAILBOX,         op_main_next_unread_mailbox,       CHECK_IN_MAILBOX },
  { OP_MAIN_PARENT_MESSAGE,              op_main_root_message,              CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_PREV_NEW,                    op_main_next_new,                  CHECK_NO_FLAGS },
  { OP_MAIN_PREV_NEW_THEN_UNREAD,        op_main_next_new,                  CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_PREV_SUBTHREAD,              op_main_next_thread,               CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_PREV_THREAD,                 op_main_next_thread,               CHECK_NO_FLAGS },
  { OP_MAIN_PREV_UNDELETED,              op_main_prev_undeleted,            CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_PREV_UNREAD,                 op_main_next_new,                  CHECK_NO_FLAGS },
  { OP_MAIN_QUASI_DELETE,                op_main_quasi_delete,              CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_READ_SUBTHREAD,              op_main_read_thread,               CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY },
  { OP_MAIN_READ_THREAD,                 op_main_read_thread,               CHECK_NO_FLAGS },
  { OP_MAIN_ROOT_MESSAGE,                op_main_root_message,              CHECK_NO_FLAGS },
  { OP_MAIN_SET_FLAG,                    op_main_set_flag,                  CHECK_NO_FLAGS },
  { OP_MAIN_SHOW_LIMIT,                  op_main_show_limit,                CHECK_IN_MAILBOX },
  { OP_MAIN_SYNC_FOLDER,                 op_main_sync_folder,               CHECK_NO_FLAGS },
  { OP_MAIN_TAG_PATTERN,                 op_main_tag_pattern,               CHECK_IN_MAILBOX },
  { OP_MAIN_UNDELETE_PATTERN,            op_main_undelete_pattern,          CHECK_IN_MAILBOX | CHECK_READONLY },
  { OP_MAIN_UNTAG_PATTERN,               op_main_untag_pattern,             CHECK_IN_MAILBOX },
  { OP_MARK_MSG,                         op_mark_msg,                       CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MIDDLE_PAGE,                      op_menu_move,                      CHECK_NO_FLAGS },
  { OP_NEXT_ENTRY,                       op_next_entry,                     CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_NEXT_LINE,                        op_menu_move,                      CHECK_NO_FLAGS },
  { OP_NEXT_PAGE,                        op_menu_move,                      CHECK_NO_FLAGS },
  { OP_PIPE,                             op_pipe,                           CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_PREV_ENTRY,                       op_prev_entry,                     CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_PREV_LINE,                        op_menu_move,                      CHECK_NO_FLAGS },
  { OP_PREV_PAGE,                        op_menu_move,                      CHECK_NO_FLAGS },
  { OP_PRINT,                            op_print,                          CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_PURGE_MESSAGE,                    op_delete,                         CHECK_NO_FLAGS },
  { OP_PURGE_THREAD,                     op_delete_thread,                  CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY },
  { OP_QUERY,                            op_query,                          CHECK_ATTACH },
  { OP_QUIT,                             op_quit,                           CHECK_NO_FLAGS },
  { OP_RECALL_MESSAGE,                   op_recall_message,                 CHECK_ATTACH },
  { OP_REDRAW,                           op_redraw,                         CHECK_NO_FLAGS },
  { OP_REPLY,                            op_post,                           CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_ATTACH },
  { OP_RESEND,                           op_resend,                         CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_ATTACH },
  { OP_SAVE,                             op_save,                           CHECK_NO_FLAGS },
  { OP_SEARCH,                           op_search,                         CHECK_IN_MAILBOX },
  { OP_SEARCH_NEXT,                      op_search,                         CHECK_NO_FLAGS },
  { OP_SEARCH_OPPOSITE,                  op_search,                         CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_SEARCH_REVERSE,                   op_search,                         CHECK_NO_FLAGS },
  { OP_SHELL_ESCAPE,                     op_shell_escape,                   CHECK_NO_FLAGS },
  { OP_SHOW_LOG_MESSAGES,                op_show_log_messages,              CHECK_NO_FLAGS },
  { OP_SORT,                             op_sort,                           CHECK_NO_FLAGS },
  { OP_SORT_REVERSE,                     op_sort,                           CHECK_NO_FLAGS },
  { OP_TAG,                              op_tag,                            CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_TAG_SUBTHREAD,                    op_tag_thread,                     CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_TAG_THREAD,                       op_tag_thread,                     CHECK_NO_FLAGS },
  { OP_TOGGLE_NEW,                       op_toggle_new,                     CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY },
  { OP_TOGGLE_READ,                      op_main_limit,                     CHECK_IN_MAILBOX },
  { OP_TOGGLE_WRITE,                     op_toggle_write,                   CHECK_IN_MAILBOX },
  { OP_TOP_PAGE,                         op_menu_move,                      CHECK_NO_FLAGS },
  { OP_UNDELETE,                         op_undelete,                       CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY },
  { OP_UNDELETE_SUBTHREAD,               op_undelete_thread,                CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY },
  { OP_UNDELETE_THREAD,                  op_undelete_thread,                CHECK_NO_FLAGS },
  { OP_VERSION,                          op_version,                        CHECK_NO_FLAGS },
  { OP_VIEW_ATTACHMENTS,                 op_view_attachments,               CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_VIEW_RAW_MESSAGE,                 op_edit_raw_message,               CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_ATTACH },
  { OP_WHAT_KEY,                         op_what_key,                       CHECK_NO_FLAGS },
#ifdef USE_AUTOCRYPT
  { OP_AUTOCRYPT_ACCT_MENU,              op_autocrypt_acct_menu,            CHECK_NO_FLAGS },
#endif
#ifdef USE_IMAP
  { OP_MAIN_IMAP_FETCH,                  op_main_imap_fetch,                CHECK_NO_FLAGS },
  { OP_MAIN_IMAP_LOGOUT_ALL,             op_main_imap_logout_all,           CHECK_NO_FLAGS },
#endif
#ifdef USE_NNTP
  { OP_CATCHUP,                          op_catchup,                        CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_READONLY | CHECK_ATTACH },
  { OP_FOLLOWUP,                         op_post,                           CHECK_NO_FLAGS },
  { OP_FORWARD_TO_GROUP,                 op_post,                           CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_GET_CHILDREN,                     op_get_children,                   CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE | CHECK_READONLY | CHECK_ATTACH },
  { OP_GET_MESSAGE,                      op_get_message,                    CHECK_IN_MAILBOX | CHECK_READONLY | CHECK_ATTACH },
  { OP_GET_PARENT,                       op_get_message,                    CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_CHANGE_GROUP,                op_main_change_group,              CHECK_NO_FLAGS },
  { OP_MAIN_CHANGE_GROUP_READONLY,       op_main_change_group,              CHECK_NO_FLAGS },
  { OP_POST,                             op_post,                           CHECK_IN_MAILBOX | CHECK_ATTACH },
  { OP_RECONSTRUCT_THREAD,               op_get_children,                   CHECK_NO_FLAGS },
#endif
#ifdef USE_NOTMUCH
  { OP_MAIN_CHANGE_VFOLDER,              op_main_change_folder,             CHECK_NO_FLAGS },
  { OP_MAIN_ENTIRE_THREAD,               op_main_entire_thread,             CHECK_IN_MAILBOX | CHECK_MSGCOUNT | CHECK_VISIBLE },
  { OP_MAIN_VFOLDER_FROM_QUERY,          op_main_vfolder_from_query,        CHECK_NO_FLAGS },
  { OP_MAIN_VFOLDER_FROM_QUERY_READONLY, op_main_vfolder_from_query,        CHECK_NO_FLAGS },
  { OP_MAIN_WINDOWED_VFOLDER_BACKWARD,   op_main_windowed_vfolder_backward, CHECK_IN_MAILBOX },
  { OP_MAIN_WINDOWED_VFOLDER_FORWARD,    op_main_windowed_vfolder_forward,  CHECK_IN_MAILBOX },
#endif
#ifdef USE_POP
  { OP_MAIN_FETCH_MAIL,                  op_main_fetch_mail,                CHECK_ATTACH },
#endif
#ifdef USE_SIDEBAR
  { OP_SIDEBAR_FIRST,                    op_sidebar_next,                   CHECK_NO_FLAGS },
  { OP_SIDEBAR_LAST,                     op_sidebar_next,                   CHECK_NO_FLAGS },
  { OP_SIDEBAR_NEXT,                     op_sidebar_next,                   CHECK_NO_FLAGS },
  { OP_SIDEBAR_NEXT_NEW,                 op_sidebar_next,                   CHECK_NO_FLAGS },
  { OP_SIDEBAR_OPEN,                     op_sidebar_open,                   CHECK_NO_FLAGS },
  { OP_SIDEBAR_PAGE_DOWN,                op_sidebar_next,                   CHECK_NO_FLAGS },
  { OP_SIDEBAR_PAGE_UP,                  op_sidebar_next,                   CHECK_NO_FLAGS },
  { OP_SIDEBAR_PREV,                     op_sidebar_next,                   CHECK_NO_FLAGS },
  { OP_SIDEBAR_PREV_NEW,                 op_sidebar_next,                   CHECK_NO_FLAGS },
  { OP_SIDEBAR_TOGGLE_VISIBLE,           op_sidebar_toggle_visible,         CHECK_NO_FLAGS },
#endif
  // clang-format on
  { 0, NULL, CHECK_NO_FLAGS },
};
