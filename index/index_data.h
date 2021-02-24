/**
 * @file
 * Data shared between Index, Pager and Sidebar
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

#ifndef MUTT_INDEX_INDEX_DATA_H
#define MUTT_INDEX_INDEX_DATA_H

struct Account;
struct ConfigSubset;
struct Context;
struct CurrentEmail;
struct Email;
struct Mailbox;
struct MuttWindow;
struct Notify;

/**
 * struct CurrentEmail - Keep track of the currently selected Email
 */
struct CurrentEmail
{
  struct Email *e; ///< Current email
  size_t sequence; ///< Sequence of the current email
};

/**
 * struct IndexData - Data shared between Index, Pager and Sidebar
 */
struct IndexData
{
  struct ConfigSubset *sub; ///< Config set to use
  struct Context *ctx;      ///< Current Mailbox view
  struct Account *account;  ///< Current Account
  struct Mailbox *mailbox;  ///< Current Mailbox
  struct Email *email;      ///< Currently selected Email
  struct Notify *notify;    ///< Notifications handler

  bool done;
  bool tag;
  int newcount;
  int oldcount;
  struct CurrentEmail cur;
  bool do_mailbox_notify;
  int close;
  int attach_msg;
  bool in_pager;
};

void              index_data_free(struct MuttWindow *win, void **ptr);
struct IndexData *index_data_new (void);

#endif /* MUTT_INDEX_INDEX_DATA_H */
