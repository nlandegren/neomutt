/**
 * @file
 * GUI manage the main index (list of emails)
 *
 * @authors
 * Copyright (C) 2018 Richard Russon <rich@flatcap.org>
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
 * @page lib_index INDEX: GUI manage the main index (list of emails)
 *
 * GUI manage the main index (list of emails)
 *
 * | File               | Description              |
 * | :----------------- | :----------------------- |
 * | index/config.c     | @subpage index_config    |
 * | index/functions.c  | @subpage index_functions |
 * | index/index.c      | @subpage index_index     |
 * | index/index_data.c | @subpage index_data      |
 */

#ifndef MUTT_INDEX_H
#define MUTT_INDEX_H

#include <stdbool.h>
#include <stdio.h>
#include "index_data.h"
#include "mx.h"

struct Context;
struct Email;
struct Mailbox;
struct Menu;
struct MuttWindow;
struct NotifyCallback;

typedef uint8_t NotifyIndex;         ///< Flags, e.g. #NT_INDEX_ACCOUNT
#define NT_INDEX_NO_FLAGS        0   ///< No flags are set
#define NT_INDEX_CONFIG    (1 << 0)  ///< Config subset has changed
#define NT_INDEX_CONTEXT   (1 << 1)  ///< Context has changed
#define NT_INDEX_ACCOUNT   (1 << 2)  ///< Account has changed
#define NT_INDEX_MAILBOX   (1 << 3)  ///< Mailbox has changed
#define NT_INDEX_EMAIL     (1 << 4)  ///< Email has changed
#define NT_INDEX_CLOSING   (1 << 5)  ///< The Index is about to close

int  index_color(int line);
void index_make_entry(char *buf, size_t buflen, struct Menu *menu, int line);
void mutt_draw_statusline(int cols, const char *buf, size_t buflen);
int  mutt_index_menu(struct MuttWindow *dlg);
void mutt_set_header_color(struct Mailbox *m, struct Email *e);
void mutt_update_index(struct Menu *menu, struct Context *ctx, int check, int oldcount, const struct Email *curr_email);
struct MuttWindow *index_pager_init(struct ConfigSubset *sub, struct Context *ctx);
void index_pager_shutdown(struct MuttWindow *dlg);
int mutt_dlgindex_observer(struct NotifyCallback *nc);
bool check_acl(struct Mailbox *m, AclFlags acl, const char *msg);
int ci_next_undeleted(struct Mailbox *m, int msgno);
void set_current_email(struct CurrentEmail *cur, struct Email *e);
void update_index(struct Menu *menu, struct Context *ctx, enum MxStatus check, int oldcount, const struct CurrentEmail *cur);
void change_folder_mailbox(struct Menu *menu, struct Mailbox *m, int *oldcount, const struct CurrentEmail *cur, bool read_only);
void collapse_all(struct Context *ctx, struct Menu *menu, int toggle);
void change_folder_string(struct Menu *menu, char *buf, size_t buflen, int *oldcount, const struct CurrentEmail *cur, bool *pager_return, bool read_only);
int ci_previous_undeleted(struct Mailbox *m, int msgno);
int ci_first_message(struct Mailbox *m);
void resort_index(struct Context *ctx, struct Menu *menu);
int mx_toggle_write(struct Mailbox *m);
extern const struct Mapping IndexNewsHelp[];
struct Mailbox *change_folder_notmuch(struct Menu *menu, char *buf, int buflen, int *oldcount, const struct CurrentEmail *cur, bool read_only);

bool config_init_index(struct ConfigSet *cs);

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

#endif /* MUTT_INDEX_H */
