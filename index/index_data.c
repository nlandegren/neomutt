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

/**
 * @page index_data Data shared between Index, Pager and Sidebar
 *
 * Data shared between Index, Pager and Sidebar
 */

#include "config.h"
#include "mutt/lib.h"
#include "gui/lib.h"
#include "index_data.h"
#include "lib.h"

/**
 * index_data_free - Free Index Data
 * @param win Window
 * @param ptr Index Data to free
 *
 * Only `notify` is owned by IndexData and should be freed.
 */
void index_data_free(struct MuttWindow *win, void **ptr)
{
  if (!ptr || !*ptr)
    return;

  struct IndexData *idata = *ptr;

  notify_send(idata->notify, NT_INDEX, NT_INDEX_CLOSING, NULL);
  notify_free(&idata->notify);

  FREE(ptr);
}

/**
 * index_data_new - Create new Index Data
 * @retval ptr New IndexData
 */
struct IndexData *index_data_new(void)
{
  struct IndexData *idata = mutt_mem_calloc(1, sizeof(struct IndexData));

  idata->notify = notify_new();

  return idata;
}
