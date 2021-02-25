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

#ifndef MUTT_INDEX_FUNCTIONS_H
#define MUTT_INDEX_FUNCTIONS_H

struct IndexData;
struct Menu;

/**
 * enum IndexRetval - XXX
 */
enum IndexRetval
{
  IR_ERROR   = -2,
  IR_WARNING = -1,
  IR_SUCCESS =  0,
  IR_NOT_IMPL,
  IR_NO_ACTION,
  IR_VOID,
  IR_CONTINUE,
  IR_BREAK,
};

/**
 * typedef index_function_t - Perform an Index Function
 */
typedef enum IndexRetval (*index_function_t)(struct Menu *menu, int op, struct IndexData *idata);

/**
 * struct IndexFunction - XXX
 */
struct IndexFunction
{
  int op;
  index_function_t function;
  int flags;
  struct IndexData *idata;
};

extern struct IndexFunction IndexFunctions[];

#endif /* MUTT_INDEX_FUNCTIONS_H */
