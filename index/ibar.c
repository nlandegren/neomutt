/**
 * @file
 * Index Bar (status)
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
 * @page index_ibar Index Bar (status)
 *
 * Index Bar (status)
 */

#include "config.h"
#include <assert.h>
#include "gui/lib.h"
#include "lib.h"
#include "context.h"
#include "index_data.h"
#include "status.h"

static int recalc_count = 0;
static int repaint_count = 0;
static int event_count = 0;

/**
 * ibar_free - Free the private data attached to the MuttWindow - Implements MuttWindow::wdata_free()
 */
static void ibar_free(struct MuttWindow *win, void **ptr)
{
}

/**
 * ibar_recalc - Recalculate the Window data - Implements MuttWindow::recalc()
 */
static int ibar_recalc(struct MuttWindow *win)
{
  recalc_count++;
  return 0;
}

/**
 * ibar_repaint - Repaint the Window - Implements MuttWindow::repaint()
 */
static int ibar_repaint(struct MuttWindow *win)
{
  repaint_count++;
  if (!mutt_window_is_visible(win))
    return 0;

  char buf[1024] = { 0 };
  mutt_window_move(win, 0, 0);
  mutt_curses_set_color(MT_COLOR_QUOTED);
  int debug_len = snprintf(buf, sizeof(buf), "(E%d,C%d,P%d) ", event_count, recalc_count, repaint_count);
  mutt_window_clrtoeol(win);

  struct MuttWindow *dlg = dialog_find(win);
  if (!dlg)
    return 0;

  struct IndexData *idata = dlg->wdata;

  const char *c_status_format = cs_subset_string(idata->sub, "status_format");
  menu_status_line(buf + debug_len, sizeof(buf) - debug_len, idata->ctx->menu, idata->mailbox, NONULL(c_status_format));
  mutt_window_move(win, 0, 0);
  mutt_curses_set_color(MT_COLOR_STATUS);
  mutt_draw_statusline(win->state.cols, buf, sizeof(buf));
  mutt_curses_set_color(MT_COLOR_NORMAL);

  const bool c_ts_enabled = cs_subset_bool(idata->sub, "ts_enabled");
  if (c_ts_enabled && TsSupported)
  {
    const char *c_ts_status_format = cs_subset_string(idata->sub, "ts_status_format");
    menu_status_line(buf, sizeof(buf), idata->ctx->menu, idata->mailbox, NONULL(c_ts_status_format));
    mutt_ts_status(buf);
    const char *c_ts_icon_format = cs_subset_string(idata->sub, "ts_icon_format");
    menu_status_line(buf, sizeof(buf), idata->ctx->menu, idata->mailbox, NONULL(c_ts_icon_format));
    mutt_ts_icon(buf);
  }

  return 0;
}

/**
 * ibar_index_observer - Listen for changes to the Index - Implements ::observer_t
 */
static int ibar_index_observer(struct NotifyCallback *nc)
{
  event_count++;

  if (!nc->global_data)
    return -1;
  if (nc->event_type != NT_INDEX)
    return 0;

  struct MuttWindow *win_ibar = nc->global_data;
  if (!win_ibar)
    return 0;

  struct MuttWindow *dlg = dialog_find(win_ibar);
  if (!dlg)
    return 0;

  struct IndexData *idata = dlg->wdata;

  if (idata->done)
    ;

  return 0;
}

/**
 * ibar_create - Create the Index Bar (status)
 * @param parent Parent Window
 */
struct MuttWindow *ibar_create(struct MuttWindow *parent)
{
  // Find the root Window (the Index Dialog)
  struct MuttWindow *dlg = parent;
  for (; dlg; dlg = dlg->parent)
  {
    if (dlg->type == WT_DLG_INDEX)
      break;
  }

  assert(dlg);

  struct MuttWindow *win_ibar =
      mutt_window_new(WT_INDEX_BAR, MUTT_WIN_ORIENT_VERTICAL,
                      MUTT_WIN_SIZE_FIXED, MUTT_WIN_SIZE_UNLIMITED, 1);

  win_ibar->wdata_free = ibar_free;
  win_ibar->recalc = ibar_recalc;
  win_ibar->repaint = ibar_repaint;

  notify_observer_add(dlg->notify, NT_INDEX, ibar_index_observer, win_ibar);

  return win_ibar;
}
